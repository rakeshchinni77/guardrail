# GuardRail — Prompt-Injection Exfiltration Lab & Defense Evaluator

> **IMPORTANT WARNING**  
> GuardRail is an experimental research and evaluation platform designed to test how bounded AI agents handle malicious instructions embedded in untrusted web content. It is an evaluation and benchmarking tool, **not a guarantee of security** or an impenetrable boundary on its own.

---

## 1. Project Overview & Purpose

GuardRail evaluates agent containment, prompt-injection defenses, and failure recovery within isolated **Celesto sandboxes (microVMs)**. Real-world AI agents require dangerous capabilities: executing shell commands, reading/writing files, installing packages, and browsing websites. Running untrusted agent actions on host infrastructure risks destructive commands, secret leakage, or prompt-injection exfiltration.

GuardRail pairs a trusted control plane and audit ledger with untrusted Celesto microVM execution environments to evaluate whether defense layers successfully contain adversarial attempts.

---

## 2. Threat Model

When an AI agent browses external websites or processes unvetted documents:
- **Direct & Indirect Prompt Injection**: Untrusted page content attempts to hijack the model's instructions (e.g., instructing the agent to ignore prior commands and execute exfiltration routines).
- **Secret & Canary Exfiltration**: Malicious instructions instruct the agent to inspect environment variables, read local credentials, or transmit sensitive canaries via outbound web requests.
- **Destructive File/System Actions**: Rogue tool instructions may attempt filesystem deletion (`rm -rf`) or unauthorized state tampering.
- **Supply-Chain Attacks**: Agents may be coerced into downloading and running unvetted external scripts or packages.

GuardRail isolates all agent tool execution inside Celesto guest sandboxes, testing multi-layer defenses (network policy allowlists, pre-command safety hooks, and canary detectors) to evaluate if attacks are contained.

---

## 3. High-Level Intended Architecture

The architecture strictly segregates trusted and untrusted operations:

1. **Trusted Control Plane (Host / Docker Compose)**:
   - **FastAPI Service**: Coordinates evaluations, enforces pre-execution safety hooks, and logs audit events.
   - **PostgreSQL Run Ledger**: Stores immutable run records, command attempts, policy decisions, and evaluation outcomes.
2. **Untrusted Guest Execution (Celesto Sandboxes)**:
   - All tool invocations (`run_shell`, browser automation, file reading/writing) execute exclusively inside Celesto microVMs (`celesto_sandbox`).
   - MicroVMs provide kernel-level hardware virtualization isolation.
3. **Safety & Policy Checks**:
   - **Safety Hooks**: Inspect and block dangerous commands before execution in the guest.
   - **Network Policy**: Enforces outbound network restrictions or full isolation to prevent exfiltration.
   - **Canary Detector**: Traps any attempt to expose synthetic canary credentials.
4. **Evaluation & Evidence Reporting**:
   - Automated runners execute clean and poisoned test tasks, collecting verifiable telemetry, latency metrics, and audit traces.

---

## 4. Current Project Status

| Component | Status | Details |
|---|---|---|
| **Repository Skeleton & Config** | **Verified (Phase 1)** | Package layout, typed `app/config.py`, pytest, and ruff configured. |
| **Manual Celesto Cloud Smoke Test** | **Verified (Phase 0)** | Manual cloud VM creation, command execution, and cleanup verified. |
| **Automated Celesto Lifecycle Adapter** | *Planned (Phase 3)* | Programmatic create/execute/delete adapter not yet implemented. |
| **Docker Compose & PostgreSQL Ledger** | *Planned (Phase 2)* | Database schema, migrations, and API control plane not yet implemented. |
| **Agent & Browser Toolchain** | *Planned (Phase 4)* | Bounded agent loop and CDP browser tools not yet implemented. |
| **Defenses & Containment Suite** | *Planned (Phase 5)* | Safety callbacks and network policy enforcement not yet implemented. |
| **Evaluations & Failure Recovery** | *Planned (Phases 6–9)* | 20-run evaluation and Step-7 recovery not yet implemented. |

---

## 5. Environment & Platform Notes

GuardRail is developed on a dual Windows 11 + Ubuntu on WSL2 setup:
- **Windows 11**: Primary development environment, Antigravity IDE, unit testing, and Docker Desktop host.
- **Ubuntu on WSL2**: Linux execution environment used for Celesto CLI operations and local microVM compatibility.

> **Note on Virtual Environments**:  
> The Windows virtual environment (`.venv`) and Linux virtual environment (`.venv-linux`) are strictly distinct. Do not share or copy site-packages between them.

---

## 6. Setup & Installation

### Windows Virtual Environment
```powershell
# Create virtual environment if not present
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install package in editable mode with development dependencies
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Environment Configuration
Copy the provided template and configure any needed values:
```powershell
Copy-Item .env.example .env
```
*(Leave placeholder values intact for Phase 1 testing; live credentials are not required for local unit tests.)*

---

## 7. Testing & Quality Checks

Run the standard development test and lint suite:

```bash
# Run unit tests
python -m pytest -q

# Run Ruff linter
python -m ruff check .

# Run Ruff format check
python -m ruff format --check .
```

---

## 8. Secret Hygiene & Security Guidelines

- **Never commit `.env`**: `.gitignore` strictly excludes `.env` and credential files.
- **No live credentials in repo**: Always use placeholders in documentation and example files.
- **Masked secrets**: All sensitive configuration fields use Pydantic `SecretStr` to prevent accidental logging or exposure.
- **Celesto isolation**: When Celesto sandboxes are introduced, agent tools execute inside the guest, never on the host machine.

---

## 9. Implementation Phases

| Phase | Description | Status |
|---|---|---|
| **Phase 00** | Celesto Cloud Manual Smoke Test | **Completed** |
| **Phase 01** | Repository Skeleton, Configuration & Test Foundation | **Completed** |
| **Phase 02** | Docker Compose Control Plane & PostgreSQL Ledger | Planned |
| **Phase 03** | Celesto Lifecycle Integration & MicroVM Adapter | Planned |
| **Phase 04** | Research Agent & Sandboxed Browser Tools | Planned |
| **Phase 05** | Prompt-Injection Defenses & Containment Proof | Planned |
| **Phase 06** | Ten-Step Workflow & Step-7 Failure Recovery | Planned |
| **Phase 07** | 20-Run Reliability Evaluator & Postmortem | Planned |
| **Phase 08** | Concurrency, Lifecycle & Stress Testing | Planned |
| **Phase 09** | Reports & Evidence Pipeline | Planned |
| **Phase 10** | End-to-End Hardening & Clean Checkout | Planned |
| **Phase 11** | Documentation, Demo & Final Submission | Planned |
