# Why Secure Matter? Formal Models & Attacks for the Matter Protocol

> **Abstract**
> This repository contains **ProVerif** models and execution traces to analyze key components of the **Matter** protocol, focusing on **OTA (Over-the-Air) updates**, **BDX** transfer. The **clean** models encode the intended security goals (authenticity, integrity, anti-rollback), while the **attack** models explore adverse conditions and abuse scenarios. The proofs document expected events (e.g., `VersionAccepted`, `OTAEnd`) and highlight when such guarantees may fail. The results help identify which properties hold under idealized variants and which degrade under weakened assumptions.


The repository contains the code and resources that supplement my work on the security analysis and evaluation of the Matter OTA Workflow. Below is an overview of the repository contents and structure.

## Repository Structure

The repository is organized into four main areas: `clean-models`, `attack-models`, `sessions-proofs`, and `outputs`.

* **clean-models/** — Baseline models faithful to the specification (OTA, BDX) to verify primary security goals.
  *-:* `OTA_Matter_baseline.pv`, `BDX_sync.pv`.

* **attack-models/** — Variants under adversarial conditions to expose goal breakdowns or critical assumptions.
  *-:* `OTA_attack_complete.pv`, `OTA_attack_session_keys.pv`.

* **sessions-proofs/** — Proofs and models for session phases (CASE/resumption) with dedicated events and queries (from [https://eprint.iacr.org/2025/1268](https://eprint.iacr.org/2025/1268)).
  *-:* `case.pv`, `case_resumption.pv`.

* **outputs/** — ProVerif traces and results for reproducibility (execution logs and key events).
  *-:* `OTA_Baseline.txt`, `BDX_sync.txt`, `OTA_attack_session.txt`, `OTA_attack_complete.txt`.

## Directory Tree

```bash
├── attack-models
│   ├── OTA_attack_complete.pv
│   └── OTA_attack_session_keys.pv
├── clean-models
│   ├── OTA_Matter_baseline.pv
│   └── BDX_sync.pv
├── sessions-proofs
│   ├── case.pv
│   └── case_resumption.pv
└── outputs
    ├── OTA_Baseline.txt
    ├── BDX_sync.txt
    ├── OTA_attack_session.txt
    └── OTA_attack_complete.txt
```

