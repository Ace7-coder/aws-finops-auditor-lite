# AWS FinOps Auditor (Lite)

A lightweight, local Python CLI tool designed to detect orphaned AWS resources and identify hidden infrastructure waste before it compounds into financial debt.

This repository contains the **free core-logic preview** for analyzing basic AWS usage data.

## 🚀 Upgrade to Enterprise: Automated Remediation

Want to stop manually deleting orphaned resources? The **Enterprise AWS FinOps Auditor** is a complete, automated multi-region financial cost waste calculator and remediation engine.

**Enterprise Exclusive Features:**
* **Automated Multi-Region Scanning:** Scans all active AWS regions simultaneously.
* **Zero-Setup Credential Handling:** Automatically assumes cross-account roles.
* **Slack & Teams Integrations:** Pushes daily/weekly waste reports directly to your engineering channels.
* **1-Click Remediation:** Generates execution scripts to instantly delete orphaned resources.

👉 [Download the Enterprise Engine Here](https://aisser.gumroad.com/l/vpcju)

---

## Lite Version Overview

The free Lite engine runs a local parallel pipeline against exported AWS billing or usage CSVs. It executes multi-vector financial cost waste calculations to flag:
* Unattached EBS Volumes
* Idle EC2 Instances (CPU < 5%)
* Unassociated Elastic IPs
* Public-facing security anomalies

### Quickstart

1. Clone the repository:
   ```bash
   git clone [https://github.com/Ace7-coder/aws-finops-auditor-lite.git](https://github.com/Ace7-coder/aws-finops-auditor-lite.git)
   cd aws-finops-auditor-lite
