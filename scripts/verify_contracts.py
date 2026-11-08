"""Independent compliance and contract verification script for GuardRail Phase 13."""

import json
import re
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def verify_all_contracts() -> bool:
    print("Verifying GuardRail submission artifacts against hackathon contracts...\n")

    # Contract 3: problem.json
    p3 = json.loads((WORKSPACE_ROOT / "reports/problem.json").read_text(encoding="utf-8"))
    assert len(p3["who"]) >= 40, "who < 40 chars"
    assert len(p3["agent_work"]) >= 40, "agent_work < 40 chars"
    assert len(p3["proof_output"]) >= 20, "proof_output < 20 chars"
    assert p3["idea_source"] in ("idea_bank", "original"), "idea_source invalid"
    print("[PASS] Contract 3: reports/problem.json")

    # Contract 4: commands.jsonl
    raw_lines = (WORKSPACE_ROOT / "logs/commands.jsonl").read_text(encoding="utf-8").splitlines()
    cmds = [json.loads(line) for line in raw_lines if line.strip()]
    assert len(cmds) >= 10, "commands.jsonl count < 10"
    assert all(c["execution_target"] == "celesto_sandbox" for c in cmds)
    assert all(c["decision"] in ("allow", "block") for c in cmds)
    assert all(re.match(r"^sbx-[a-z0-9]{8,}$", c["sandbox_name"]) for c in cmds)
    allow_cnt = sum(1 for c in cmds if c["decision"] == "allow")
    block_cnt = sum(1 for c in cmds if c["decision"] == "block")
    print(f"[PASS] Contract 4: logs/commands.jsonl ({len(cmds)} cmds: {allow_cnt}/{block_cnt})")

    # Contract 5: capabilities.json
    p5 = json.loads((WORKSPACE_ROOT / "reports/capabilities.json").read_text(encoding="utf-8"))
    allowed_caps = {
        "persistence",
        "snapshots",
        "celestofs",
        "browser",
        "published_ports",
        "network_policy",
        "safety_hooks",
        "host_mounts",
        "coding_agent_preset",
        "agentor_durable",
    }
    assert len(p5["capabilities"]) >= 2, "capabilities count < 2"
    assert all(c["id"] in allowed_caps for c in p5["capabilities"])
    assert len({c["id"] for c in p5["capabilities"]}) == len(p5["capabilities"])
    assert all(len(c["why"]) >= 80 for c in p5["capabilities"])
    assert all((WORKSPACE_ROOT / c["evidence_path"]).exists() for c in p5["capabilities"])
    print(f"[PASS] Contract 5: reports/capabilities.json ({len(p5['capabilities'])} unique caps)")

    # Contract 6: lifecycle.json
    p6 = json.loads((WORKSPACE_ROOT / "reports/lifecycle.json").read_text(encoding="utf-8"))
    assert p6["cleanup_on_success"] is True
    assert p6["cleanup_on_failure"] is True
    assert p6["cleanup_on_interrupt"] is True
    assert isinstance(p6["sandbox_names"], list) and len(p6["sandbox_names"]) >= 1
    assert all(re.match(r"^sbx-[a-z0-9]{8,}$", s) for s in p6["sandbox_names"])
    print(f"[PASS] Contract 6: reports/lifecycle.json ({len(p6['sandbox_names'])} sandboxes)")

    # Contract 7: reliability.json & postmortem.md
    p7 = json.loads((WORKSPACE_ROOT / "reports/reliability.json").read_text(encoding="utf-8"))
    assert p7["run_count"] >= 20
    assert len(p7["runs"]) == p7["run_count"]
    assert all(re.match(r"^sbx-[a-z0-9]{8,}$", r["sandbox_name"]) for r in p7["runs"])
    assert all(r["fresh"] is True for r in p7["runs"])
    assert all(isinstance(r["success"], bool) for r in p7["runs"])
    assert all(r["boot_to_ready_s"] >= 0 for r in p7["runs"])
    assert all(r["cost_usd"] >= 0 for r in p7["runs"])
    expected_rate = round(sum(1 for r in p7["runs"] if r["success"]) / p7["run_count"], 4)
    assert abs(p7["success_rate"] - expected_rate) < 0.001
    assert (WORKSPACE_ROOT / p7["postmortem_path"]).exists()
    pm = (WORKSPACE_ROOT / p7["postmortem_path"]).read_text(encoding="utf-8")
    assert len(pm) >= 200
    print(f"[PASS] Contract 7: reports/reliability.json (rate={p7['success_rate']})")

    # Contract 8: containment.json
    p8 = json.loads((WORKSPACE_ROOT / "reports/containment.json").read_text(encoding="utf-8"))
    assert p8["attack"] in ("prompt_injection_exfil", "destructive_command", "suspicious_package")
    assert p8["blocked"] is True
    assert p8["host_untouched"] is True
    assert len(p8["evidence_paths"]) >= 1
    assert all((WORKSPACE_ROOT / e).exists() for e in p8["evidence_paths"])
    print(f"[PASS] Contract 8: reports/containment.json (attack={p8['attack']})")

    # Contract 9: failure_policy.json & failure_trace.jsonl
    p9 = json.loads((WORKSPACE_ROOT / "reports/failure_policy.json").read_text(encoding="utf-8"))
    assert p9["failed_step"] == 7
    assert p9["total_steps"] == 10
    assert p9["policy"] in ("resume", "rollback", "fresh")
    assert len(p9["rationale"]) >= 200
    assert (WORKSPACE_ROOT / p9["trace_path"]).exists()
    t_lines = (WORKSPACE_ROOT / p9["trace_path"]).read_text(encoding="utf-8").splitlines()
    trace = [json.loads(line) for line in t_lines if line.strip()]
    assert any(
        (o.get("event") == "policy_applied" or o.get("event_type") == "policy_applied")
        and (o.get("policy") == p9["policy"] or o.get("details", {}).get("policy") == p9["policy"])
        for o in trace
    )
    print(f"[PASS] Contract 9: reports/failure_policy.json & trace (policy={p9['policy']})")

    # Contract 10: concurrency.json
    p10 = json.loads((WORKSPACE_ROOT / "reports/concurrency.json").read_text(encoding="utf-8"))
    assert p10["total_jobs"] >= 5
    assert p10["unique_runs"] >= 5
    assert p10["unique_sandboxes"] >= 5
    assert p10["identifier_collisions"] == 0
    assert len(p10["breakage_notes"]) >= 40
    assert all(re.match(r"^sbx-[a-z0-9]{8,}$", j["sandbox_name"]) for j in p10["jobs"])
    print(f"[PASS] Contract 10: reports/concurrency.json ({p10['total_jobs']} jobs, 0 collisions)")

    print("\n=======================================================")
    print("ALL HACKATHON CONTRACTS SATISFIED AND VERIFIED!")
    print("=======================================================")
    return True


if __name__ == "__main__":
    verify_all_contracts()
