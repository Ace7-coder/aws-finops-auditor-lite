import argparse
import hashlib
import json
import os
import sys
from typing import Dict, List
import pandas as pd

ENTERPRISE_URL = "https://aisser.gumroad.com/l/krgac"


class InfrastructureAuditor:

  def __init__(self, salt: str = "infra_secure_2024"):
    self.salt = salt
    self.alias_map = {
        "cost": "amount",
        "amount": "amount",
        "usageamount": "amount",
        "unblendedcost": "amount",
        "totalcost": "amount",
        "monthly_cost_usd": "amount",
        "monthly_cost": "amount",
        "resourceid": "resource_id",
        "resource_id": "resource_id",
        "instanceid": "resource_id",
        "instance_id": "resource_id",
        "server_id": "resource_id",
        "publicip": "is_public",
        "public_ip": "is_public",
        "is_public": "is_public",
        "cpu_util": "cpu_utilization",
        "cpu_utilization": "cpu_utilization",
        "cpu": "cpu_utilization",
        "avg_cpu_usage_percent": "cpu_utilization",
        "cpu_usage": "cpu_utilization",
        "unattached_storage_cost_usd": "unattached_storage_cost",
        "unattached_storage_cost": "unattached_storage_cost",
        "is_encrypted": "is_encrypted",
        "encrypted": "is_encrypted",
    }

  def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
    new_cols = {}
    for col in df.columns:
      clean_col = str(col).strip().lower().replace(" ", "_")
      new_cols[col] = self.alias_map.get(clean_col, clean_col)
    return df.rename(columns=new_cols)

  def validate_schema(self, df: pd.DataFrame) -> None:
    missing = []
    if "amount" not in df.columns:
      missing.append("Cost/Amount (e.g., 'monthly_cost_usd', 'Cost', 'amount')")
    if "resource_id" not in df.columns:
      missing.append(
          "Resource ID (e.g., 'server_id', 'ResourceID', 'resource_id')"
      )
    if missing:
      col_list = ", ".join([f"'{c}'" for c in df.columns])
      raise ValueError(
          f"Missing required columns: {', '.join(missing)}.\nColumns detected"
          f" in file: [{col_list}]"
      )

  def anonymize_id(self, raw_id: str) -> str:
    hash_obj = hashlib.sha256(f"{str(raw_id)}{self.salt}".encode())
    return hash_obj.hexdigest()[:16]

  def process_data(self, df: pd.DataFrame) -> pd.DataFrame:
    df = self.normalize_columns(df)
    self.validate_schema(df)
    df["amount"] = pd.to_numeric(df["amount"], errors="coerce").fillna(0.0)
    df["resource_id"] = df["resource_id"].astype(str).apply(self.anonymize_id)
    return df

  def calculate_waste(self, df: pd.DataFrame) -> float:
    total_waste = 0.0
    if "cpu_utilization" in df.columns:
      cpu_series = pd.to_numeric(df["cpu_utilization"], errors="coerce")
      idle_mask = (cpu_series < 5.0) | (
          (df["amount"] > 0) & (cpu_series.isna())
      )
      total_waste += float(df.loc[idle_mask, "amount"].sum())
    else:
      waste_mask = df["amount"] > 0
      total_waste += (
          float(df.loc[waste_mask, "amount"].sum())
          if not df.loc[waste_mask].empty
          else 0.0
      )

    if "unattached_storage_cost" in df.columns:
      storage_series = pd.to_numeric(
          df["unattached_storage_cost"], errors="coerce"
      ).fillna(0.0)
      total_waste += float(storage_series.sum())

    return total_waste

  def detect_security_anomalies(self, df: pd.DataFrame) -> List[str]:
    anomalies = []
    if "is_public" in df.columns:
      is_pub = (
          df["is_public"]
          .astype(str)
          .str.strip()
          .str.lower()
          .isin(["true", "1", "yes", "t"])
      )
      public_count = int(is_pub.sum())
      if public_count > 0:
        anomalies.append(
            f"CRITICAL: {public_count} resources exposed to public internet."
        )

    if "is_encrypted" in df.columns:
      is_enc = (
          df["is_encrypted"]
          .astype(str)
          .str.strip()
          .str.lower()
          .isin(["false", "0", "no", "f"])
      )
      unencrypted_count = int(is_enc.sum())
      if unencrypted_count > 0:
        anomalies.append(
            f"HIGH: {unencrypted_count} resources are currently unencrypted."
        )

    return anomalies

  def generate_outputs(self, df: pd.DataFrame, results: Dict):
    with open("audit_report.json", "w", encoding="utf-8") as f:
      json.dump(results, f, indent=4)

    with open("executive_summary.md", "w", encoding="utf-8") as f:
      f.write("# Infrastructure Audit Summary (Lite Community Edition)\n\n")
      f.write(
          f"- **Monthly Waste Identified:** ${results['total_waste']:,.2f}/mo\n"
      )
      f.write(
          "- **Projected Annual Waste:**"
          f" ${results['annualized_waste']:,.2f}/yr\n"
      )
      f.write(f"- **Security Flags:** {len(results['anomalies'])}\n\n")
      if results["anomalies"]:
        f.write("### Security Notices\n")
        for anomaly in results["anomalies"]:
          f.write(f"- {anomaly}\n")

      f.write("\n---\n")
      f.write("### Need Enterprise Multi-Account or Client Deliverables?\n")
      f.write(
          "Upgrade to the **AWS Cloud Cost Auditor: Consultant & MSP Toolkit**"
          " to unlock:\n"
          "- **AWS Organizations Multi-Account Scanner:** Cross-account IAM"
          " role assumption across all member accounts.\n"
          "- **Client-Ready Deliverables:** Presentation-grade Markdown and PDF"
          " executive showback reports.\n"
          "- **Commercial Agency License:** Authorization to conduct commercial"
          " client assessments.\n"
          "- **Automated Remediation Engine (`--remediate`):** Shell scripts"
          " for anomaly mitigation.\n\n"
          f"**View Commercial Editions ($149/yr / $999/yr):** {ENTERPRISE_URL}\n"
      )
      f.write("\n---\n*Generated by AWS FinOps Auditor*\n")

  def run_pipeline(self, df: pd.DataFrame) -> Dict:
    df = self.process_data(df)
    waste = self.calculate_waste(df)
    anomalies = self.detect_security_anomalies(df)

    results = {
        "total_waste": round(waste, 2),
        "annualized_waste": round(waste * 12, 2),
        "anomalies": anomalies,
        "records_analyzed": len(df),
    }

    self.generate_outputs(df, results)
    return results


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="AWS FinOps Auditor")
  parser.add_argument(
      "--file", type=str, required=True, help="Path to AWS usage CSV file"
  )
  args = parser.parse_args()

  auditor = InfrastructureAuditor()
  try:
    raw_df = pd.read_csv(args.file)
    print(f"Scanning {args.file} ({len(raw_df)} records)...")

    results = auditor.run_pipeline(raw_df.copy())

    print("\nAudit Complete!")
    print("==================================================")
    print(f"Records Analyzed:        {results['records_analyzed']}")
    print(f"Monthly Waste Found:     ${results['total_waste']:,.2f}/mo")
    print(f"Projected Annual Waste:  ${results['annualized_waste']:,.2f}/yr")
    print(f"Security Flags:          {len(results['anomalies'])}")
    print("==================================================")
    print("Generated 'audit_report.json' and 'executive_summary.md'.")

    print("\n" + "=" * 70)
    print("[AWS FinOps Lite] Single-account scan complete.")
    print(
        "Need multi-account AWS Organizations scanning, client-ready showback"
    )
    print("reports, or commercial assessment rights for client accounts?")
    print(f"Consultant & MSP Toolkit ($149/yr / $999/yr): {ENTERPRISE_URL}")
    print("=" * 70 + "\n")

  except Exception as e:
    print(f"\n[!] Audit Failed: {e}", file=sys.stderr)
    sys.exit(1)