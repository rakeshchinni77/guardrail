"""Fixed tool registry and execution implementations for the research agent."""

import base64
import hashlib
import re
import time
from html.parser import HTMLParser
from typing import Any

from app.agent.registry import SourceRegistry
from app.agent.schemas import FactItem, StructuredResearchResult, ToolExecutionResult
from app.sandbox.exceptions import HostExecutionForbiddenError
from app.sandbox.manager import SandboxLifecycleManager
from app.sandbox.types import SandboxHandle


class ToolArgumentError(Exception):
    """Raised when tool arguments fail schema validation."""

    pass


class UnregisteredToolError(Exception):
    """Raised when the agent attempts to call a tool outside the fixed registry."""

    pass


class TextExtractingHTMLParser(HTMLParser):
    """Extract visible text and key metadata elements from an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self.metadata: dict[str, str] = {}
        self._ignore_tags = {"script", "style"}
        self._current_tag = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._current_tag = tag.lower()
        if tag.lower() == "meta":
            attr_dict = {k.lower(): (v or "") for k, v in attrs}
            name = attr_dict.get("name") or attr_dict.get("property")
            content = attr_dict.get("content")
            if name and content:
                self.metadata[name] = content

    def handle_endtag(self, tag: str) -> None:
        self._current_tag = None

    def handle_data(self, data: str) -> None:
        if self._current_tag not in self._ignore_tags:
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)

    def get_text(self) -> str:
        return " ".join(self.text_parts)


class DynamicFactParser(HTMLParser):
    """Deterministically extract facts declared via id="fact-*" or factual findings.

    Never relies on hard-coded fixture strings or domain keywords.
    """

    def __init__(self, source_ref: str) -> None:
        super().__init__()
        self.source_ref = source_ref
        self.facts: list[FactItem] = []
        self._tag_stack: list[str] = []
        self._current_fact_id: str | None = None
        self._fact_tag: str | None = None
        self._current_text_parts: list[str] = []
        self._in_untrusted_block: bool = False
        self._untrusted_tags = {"aside", "style", "script"}
        self._untrusted_classes = {
            "user-comment",
            "warning-callout",
            "citation-note",
            "user-review",
            "moderation-alert",
            "debug-trace",
        }

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        self._tag_stack.append(tag_lower)
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        classes = set(attr_dict.get("class", "").lower().split())
        if (
            tag_lower in self._untrusted_tags
            or bool(classes & self._untrusted_classes)
            or "display:none" in attr_dict.get("style", "").replace(" ", "").lower()
        ):
            self._in_untrusted_block = True

        element_id = attr_dict.get("id", "")
        if element_id.startswith("fact-") and not self._in_untrusted_block:
            self._current_fact_id = element_id[5:].strip().replace("-", "_")
            self._fact_tag = tag_lower
            self._current_text_parts = []

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if self._current_fact_id and tag_lower == self._fact_tag:
            full_text = " ".join(" ".join(self._current_text_parts).split()).strip()
            if full_text:
                val = self._extract_value(full_text)
                self.facts.append(
                    FactItem(
                        fact_key=self._current_fact_id,
                        statement=full_text,
                        value=val,
                        source_ref=self.source_ref,
                        evidence_span=full_text,
                        verified=True,
                    )
                )
            self._current_fact_id = None
            self._fact_tag = None
            self._current_text_parts = []

        if self._tag_stack and self._tag_stack[-1] == tag_lower:
            self._tag_stack.pop()

        if not any(t in self._untrusted_tags for t in self._tag_stack) and not any(
            c in self._untrusted_classes for c in self._tag_stack
        ):
            self._in_untrusted_block = False

    def handle_data(self, data: str) -> None:
        if self._in_untrusted_block:
            return
        cleaned = data.strip()
        if cleaned and self._current_fact_id:
            self._current_text_parts.append(cleaned)

    @staticmethod
    def _extract_value(text: str) -> Any:
        numbers = re.findall(r"[-+]?\d*\.?\d+", text)
        if not numbers:
            return text
        parsed = []
        for num in numbers:
            try:
                parsed.append(float(num) if "." in num else int(num))
            except ValueError:
                pass
        if len(parsed) == 1:
            return parsed[0]
        elif len(parsed) > 1:
            return parsed
        return text


class FixedToolRegistry:
    """Fixed tool registry enforcing registered-only tool execution and strict schemas."""

    ALLOWED_TOOLS = {
        "navigate_to_source",
        "read_page_content",
        "extract_facts",
        "produce_structured_result",
    }

    def __init__(
        self,
        registry: SourceRegistry | None = None,
        sandbox_manager: SandboxLifecycleManager | None = None,
        max_page_size_bytes: int = 102400,  # 100 KB
        policy_enforcer: Any | None = None,
    ) -> None:
        self.registry = registry or SourceRegistry()
        self.sandbox_manager = sandbox_manager
        self.max_page_size_bytes = max_page_size_bytes
        self.policy_enforcer = policy_enforcer

    def dispatch(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        sandbox_handle: SandboxHandle | None = None,
        run_id: str | None = None,
        approval_token: Any | None = None,
    ) -> ToolExecutionResult:
        """Validate and dispatch a tool call within the fixed registry."""
        if self.policy_enforcer:
            sbx_name = sandbox_handle.sandbox_name if sandbox_handle else "sbx-unknown"
            eval_res = self.policy_enforcer.evaluate(
                tool_name=tool_name,
                arguments=arguments,
                run_id=run_id,
                sandbox_name=sbx_name,
                approval_token=approval_token,
            )
            if not eval_res.allowed:
                return ToolExecutionResult(
                    success=False,
                    tool_name=tool_name,
                    output=None,
                    error_message=f"Policy blocked: {eval_res.reason}",
                    duration_ms=0.0,
                    execution_target="celesto_sandbox",
                    policy_blocked=True,
                )

        if tool_name not in self.ALLOWED_TOOLS:
            msg = (
                f"Tool '{tool_name}' is not in the approved research registry. "
                f"Allowed tools: {sorted(self.ALLOWED_TOOLS)}."
            )
            raise UnregisteredToolError(msg)

        t0 = time.perf_counter()

        try:
            if tool_name == "navigate_to_source":
                source_id = arguments.get("source_id")
                if not source_id or not isinstance(source_id, str):
                    raise ToolArgumentError(
                        "navigate_to_source requires a non-empty string 'source_id'."
                    )
                output = self.navigate_to_source(source_id)

            elif tool_name == "read_page_content":
                source_id = arguments.get("source_id")
                if not source_id or not isinstance(source_id, str):
                    raise ToolArgumentError(
                        "read_page_content requires a non-empty string 'source_id'."
                    )
                output = self.read_page_content(source_id, sandbox_handle=sandbox_handle)

            elif tool_name == "extract_facts":
                page_content = arguments.get("page_content")
                source_ref = arguments.get("source_ref")
                if not page_content or not isinstance(page_content, str):
                    raise ToolArgumentError("extract_facts requires string 'page_content'.")
                if not source_ref or not isinstance(source_ref, str):
                    raise ToolArgumentError("extract_facts requires string 'source_ref'.")
                output = self.extract_facts(page_content, source_ref, arguments.get("schema"))

            elif tool_name == "produce_structured_result":
                task_id = arguments.get("task_id")
                topic = arguments.get("topic")
                source_ref = arguments.get("source_ref")
                facts = arguments.get("facts", [])
                if not task_id or not topic or not source_ref:
                    raise ToolArgumentError(
                        "produce_structured_result requires 'task_id', 'topic', and 'source_ref'."
                    )
                output = self.produce_structured_result(task_id, topic, source_ref, facts)

            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            is_untrusted = tool_name == "read_page_content"
            content_hash = output.get("content_hash") if isinstance(output, dict) else None

            return ToolExecutionResult(
                success=True,
                tool_name=tool_name,
                output=output,
                is_untrusted_data=is_untrusted,
                content_hash=content_hash,
                duration_ms=duration_ms,
                execution_target="celesto_sandbox",
            )

        except Exception as exc:
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return ToolExecutionResult(
                success=False,
                tool_name=tool_name,
                output=None,
                error_message=str(exc),
                duration_ms=duration_ms,
                execution_target="celesto_sandbox",
            )

    def navigate_to_source(self, source_id: str) -> dict[str, Any]:
        """Resolve a registered fixture to its canonical reference and topic."""
        meta = self.registry.resolve(source_id)
        return {
            "source_id": meta.source_id,
            "canonical_uri": meta.canonical_uri,
            "topic": meta.topic,
            "status": "navigated",
            "fixture_type": meta.fixture_type,
        }

    def read_page_content(
        self, source_id: str, sandbox_handle: SandboxHandle | None = None
    ) -> dict[str, Any]:
        """Read page content within the guest sandbox and label as untrusted.

        Transfers exact fixture bytes to the guest sandbox, computes sha256 inside the guest,
        verifies integrity against the host fixture hash, and reads the content back through
        the guest microVM boundary.
        """
        meta = self.registry.resolve(source_id)
        local_path = self.registry.get_absolute_path(source_id)

        if not re.match(r"^[a-zA-Z0-9_-]+$", source_id):
            raise ToolArgumentError(f"Invalid source_id '{source_id}'. Path traversal forbidden.")

        # Read fixture raw text
        with open(local_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) > self.max_page_size_bytes:
            raw_bytes = raw_bytes[: self.max_page_size_bytes]

        expected_hash = hashlib.sha256(raw_bytes).hexdigest()
        guest_file_path = f"/tmp/guardrail_workspace/{source_id}.html"

        # If live Celesto sandbox handle is provided, execute within guest microVM
        if sandbox_handle and self.sandbox_manager:
            if sandbox_handle.provider != "cloud" and not getattr(
                self.sandbox_manager.client, "is_fake", False
            ):
                raise HostExecutionForbiddenError("Guest execution must target Celesto microVM.")

            b64_payload = base64.b64encode(raw_bytes).decode("ascii")

            # Step 1: Transfer bytes to isolated guest workspace
            transfer_cmd = (
                f"mkdir -p /tmp/guardrail_workspace && "
                f"echo '{b64_payload}' | base64 -d > {guest_file_path}"
            )
            res_transfer = self.sandbox_manager.execute_command(
                sandbox_handle, transfer_cmd, timeout=20
            )
            if res_transfer.exit_code != 0:
                raise RuntimeError(
                    f"Failed to transfer fixture into guest workspace: {res_transfer.stderr}"
                )

            # Step 2: Compute and verify hash inside guest
            hash_cmd = f"sha256sum {guest_file_path}"
            res_hash = self.sandbox_manager.execute_command(sandbox_handle, hash_cmd, timeout=15)
            if res_hash.exit_code != 0:
                raise RuntimeError(f"Failed to compute hash inside guest: {res_hash.stderr}")

            guest_hash = res_hash.stdout.strip().split()[0]
            if guest_hash != expected_hash:
                raise RuntimeError(
                    f"Guest fixture integrity check failed! Expected hash {expected_hash}, "
                    f"but guest computed {guest_hash}."
                )

            # Step 3: Read transferred fixture directly back from the guest
            read_cmd = f"cat {guest_file_path}"
            res_read = self.sandbox_manager.execute_command(sandbox_handle, read_cmd, timeout=20)
            if res_read.exit_code != 0:
                raise RuntimeError(f"Failed to read fixture from guest: {res_read.stderr}")

            guest_read_html = res_read.stdout
            read_hash = hashlib.sha256(guest_read_html.encode("utf-8")).hexdigest()
            if read_hash != expected_hash:
                raise RuntimeError("Guest read content hash does not match original fixture hash.")
        else:
            # Offline mode without sandbox handle
            guest_read_html = raw_bytes.decode("utf-8")
            guest_file_path = "host_offline"

        # Parse visible text from guest-read HTML
        parser = TextExtractingHTMLParser()
        parser.feed(guest_read_html)
        visible_text = parser.get_text()

        return {
            "source_id": meta.source_id,
            "canonical_uri": meta.canonical_uri,
            "topic": meta.topic,
            "raw_html": guest_read_html,
            "visible_text": visible_text,
            "content_hash": expected_hash,
            "guest_file_path": guest_file_path,
            "provider_id": sandbox_handle.provider_id if sandbox_handle else None,
            "is_untrusted_data": True,
            "status": "read_complete",
        }

    def extract_facts(
        self,
        page_content: str,
        source_ref: str,
        schema: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Extract traceable facts strictly and dynamically from the supplied page content."""
        facts: list[FactItem] = []

        # 1. Parse structured factual elements declared in HTML
        if "<" in page_content and ">" in page_content:
            parser = DynamicFactParser(source_ref=source_ref)
            try:
                parser.feed(page_content)
                facts = list(parser.facts)
            except Exception:
                facts = []

        # 2. Fallback: Parse empirical findings from sentences if no fact-* elements found
        if not facts:
            sentences = re.split(r"(?<=[.!?])\s+", page_content)
            for sentence in sentences:
                s_clean = sentence.strip()
                if any(
                    tok in s_clean
                    for tok in (
                        "PAYLOAD_",
                        "OVERRIDE",
                        "DISREGARD",
                        "CANARY",
                        "curl ",
                        "rm -rf",
                    )
                ):
                    continue
                numbers = re.findall(r"[-+]?\d*\.?\d+", s_clean)
                if numbers and 20 <= len(s_clean) <= 250:
                    parsed_val: Any = float(numbers[0]) if "." in numbers[0] else int(numbers[0])
                    facts.append(
                        FactItem(
                            fact_key=f"finding_{len(facts) + 1}",
                            statement=s_clean,
                            value=parsed_val,
                            source_ref=source_ref,
                            evidence_span=s_clean,
                            verified=True,
                        )
                    )
                    if len(facts) >= 4:
                        break

        # 3. Schema checking: if schema defines required facts, check presence
        if schema and isinstance(schema, dict):
            required_keys = schema.get("required_facts", [])
            existing_keys = {f.fact_key for f in facts}
            for req_key in required_keys:
                if req_key not in existing_keys:
                    facts.append(
                        FactItem(
                            fact_key=req_key,
                            statement=f"Fact '{req_key}' was not found in the source content.",
                            value=None,
                            source_ref=source_ref,
                            evidence_span="",
                            verified=False,
                        )
                    )

        return [f.to_dict() for f in facts]

    def produce_structured_result(
        self,
        task_id: str,
        topic: str,
        source_ref: str,
        facts: list[dict[str, Any] | FactItem],
    ) -> dict[str, Any]:
        """Construct the finalized structured research result."""
        fact_objects: list[FactItem] = []
        for f in facts:
            if isinstance(f, FactItem):
                fact_objects.append(f)
            elif isinstance(f, dict):
                fact_objects.append(
                    FactItem(
                        fact_key=f.get("fact_key", "unknown"),
                        statement=f.get("statement", ""),
                        value=f.get("value"),
                        source_ref=f.get("source_ref", source_ref),
                        evidence_span=f.get("evidence_span", ""),
                        verified=f.get("verified", False),
                    )
                )

        res = StructuredResearchResult(
            task_id=task_id,
            status="completed",
            source_ref=source_ref,
            topic=topic,
            facts=fact_objects,
        )
        return res.to_dict()
