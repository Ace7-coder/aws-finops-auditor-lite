# AWS FinOps Auditor (Lite)

A lightweight, local Python CLI tool designed to detect orphaned AWS resources and identify hidden infrastructure waste before it compounds into financial debt.

This repository contains the **free community edition** for analyzing basic AWS usage and billing exports.

---

### Edition Comparison

| Capability | Lite (Community) | Consultant & MSP Toolkit |
| :--- | :---: | :---: |
| Single-Account CSV Analysis | Yes | Yes |
| Orphaned Storage & Idle Compute Detection | Yes | Yes |
| Local Terminal & JSON Output | Yes | Yes |
| AWS Organizations Multi-Account Scanning (`sts:AssumeRole`) | No | **Yes** |
| Client-Ready Showback Reports (Markdown & PDF) | No | **Yes** |
| Automated 1-Click Remediation Scripts (`--remediate`) | No | **Yes** |
| Commercial Assessment License (Agency/Client Rights) | No | **Yes** |

👉 **[Get the Consultant & MSP Toolkit on Gumroad](https://aisser.gumroad.com/l/krgac)** *(Practitioner $149/yr / Agency Pack $999/yr)*

---

## 🚀 Commercial Editions: Consultant & MSP Toolkit

Built for cloud consultants, MSPs, and infrastructure teams managing multi-account environments. The commercial toolkit shifts from static single-account file analysis to automated multi-account discovery and client-facing deliverables.

- **AWS Organizations Multi-Account Engine:** Automatically discovers and assumes cross-account IAM roles across all member accounts in your AWS Organization.
- **Client-Ready Showback Reports:** Generates executive Markdown and PDF summaries with showback by department and annualized savings calculations.
- **1-Click Remediation Generator:** Auto-generates idempotent remediation scripts (`remediate_anomalies.sh`) for pull request review before deletion.
- **Commercial Assessment Rights:** Includes a formal agency license permitting paid client assessments and audits.

👉 **[Download the Commercial Toolkit](https://aisser.gumroad.com/l/krgac)**

---

## Lite Version Overview

The free Lite engine executes multi-vector cost and anomaly calculations locally against exported AWS billing or usage CSV files. It flags:
- **Unattached EBS Volumes:** Adds up the unattached-storage costs reported in your export, covering detached `gp2`, `gp3`, and `io2` volumes that keep billing every month.
- **Idle EC2 Instances:** Flags compute rows whose average CPU utilization is under 5% and counts their cost as waste.
- **Unassociated Elastic IPs:** Counts charges for unattached public IPv4 addresses included in your export, which incur hourly reservation fees.
- **Security & Configuration Anomalies:** Flags rows your export marks as unencrypted or exposed to the public internet.

### Quickstart

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ace7-coder/aws-finops-auditor-lite.git
   cd aws-finops-auditor-lite
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the auditor against the bundled sample data:**
   ```bash
   python infrastructure_auditor.py --file sample_aws_data.csv
   ```