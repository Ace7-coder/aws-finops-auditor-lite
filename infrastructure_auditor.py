import pandas as pd
import hashlib
import json
import argparse
import sys
from typing import List, Dict

# Enterprise Modules
from remediation_generator import generate_remediation_script
from compliance_exporter import generate_compliance_report

class InfrastructureAuditor:
    def __init__(self, salt: str = "infra_secure_2024"):
        self.salt = salt
        # Case-insensitive alias map
        self.alias_map = {
            'cost': 'amount',
            'amount': 'amount',
            'usageamount': 'amount',
            'unblendedcost': 'amount',
            'totalcost': 'amount',
            'monthly_cost_usd': 'amount',
            'monthly_cost': 'amount',
            
            'resourceid': 'resource_id',
            'resource_id': 'resource_id',
            'instanceid': 'resource_id',
            'instance_id': 'resource_id',
            'server_id': 'resource_id',
            
            'publicip': 'is_public',
            'public_ip': 'is_public',
            'is_public': 'is_public',
            
            'cpu_util': 'cpu_utilization',
            'cpu_utilization': 'cpu_utilization',
            'cpu': 'cpu_utilization',
            'avg_cpu_usage_percent': 'cpu_utilization',
            'cpu_usage': 'cpu_utilization',
            
            'unattached_storage_cost_usd': 'unattached_storage_cost',
            'unattached_storage_cost': 'unattached_storage_cost',
            
            'is_encrypted': 'is_encrypted',
            'encrypted': 'is_encrypted'
        }

    def normalize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize dataframe column names with case and symbol insensitivity."""
        new_cols = {}
        for col in df.columns:
            clean_col = str(col).strip().lower().replace(" ", "_")
            if clean_col in self.alias_map:
                new_cols[col] = self.alias_map[clean_col]
            else:
                new_cols[col] = clean_col # keep original normalized
        return df.rename(columns=new_cols)

    def validate_schema(self, df: pd.DataFrame) -> None:
        """Verify essential columns exist, raising helpful errors if missing."""
        missing = []
        if 'amount' not in df.columns:
            missing.append("Cost/Amount (e.g., 'monthly_cost_usd', 'Cost', 'amount')")
        if 'resource_id' not in df.columns:
            missing.append("Resource ID (e.g., 'server_id', 'ResourceID', 'resource_id')")
        
        if missing:
            col_list = ", ".join([f"'{c}'" for c in df.columns])
            raise ValueError(
                f"Missing required columns: {', '.join(missing)}.\n"
                f"Columns detected in file: [{col_list}]"
            )

    def anonymize_id(self, raw_id: str) -> str:
        """Deterministic SHA-256 data anonymizer."""
        hash_obj = hashlib.sha256(f"{str(raw_id)}{self.salt}".encode())
        return hash_obj.hexdigest()[:16]

    def process_data(self, df: pd.DataFrame) -> pd.DataFrame:
        df = self.normalize_columns(df)
        self.validate_schema(df)
        
        # Ensure numeric type on amount
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce').fillna(0.0)

        # Anonymize resource IDs for security
        df['resource_id'] = df['resource_id'].astype(str).apply(self.anonymize_id)
        return df

    def calculate_waste(self, df: pd.DataFrame) -> float:
        """Multi-vector financial cost-waste calculations."""
        total_waste = 0.0
        
        # 1. Idle Compute Waste (CPU < 5%)
        if 'cpu_utilization' in df.columns:
            cpu_series = pd.to_numeric(df['cpu_utilization'], errors='coerce')
            idle_mask = (cpu_series < 5.0) | ((df['amount'] > 0) & (cpu_series.isna()))
            total_waste += float(df.loc[idle_mask, 'amount'].sum())
        else:
            # Baseline: flag non-zero records without monitored compute activity
            waste_mask = df['amount'] > 0
            total_waste += float(df.loc[waste_mask, 'amount'].sum()) if not df.loc[waste_mask].empty else 0.0
            
        # 2. Unattached Storage Waste
        if 'unattached_storage_cost' in df.columns:
            storage_series = pd.to_numeric(df['unattached_storage_cost'], errors='coerce').fillna(0.0)
            total_waste += float(storage_series.sum())
            
        return total_waste

    def detect_security_anomalies(self, df: pd.DataFrame) -> List[str]:
        """Expanded security anomaly detection."""
        anomalies = []
        
        # Public IP Exposure
        if 'is_public' in df.columns:
            is_pub = df['is_public'].astype(str).str.strip().str.lower().isin(['true', '1', 'yes', 't'])
            public_count = int(is_pub.sum())
            if public_count > 0:
                anomalies.append(f"CRITICAL: {public_count} resources exposed to public internet.")
                
        # Unencrypted Resources
        if 'is_encrypted' in df.columns:
            is_enc = df['is_encrypted'].astype(str).str.strip().str.lower().isin(['false', '0', 'no', 'f'])
            unencrypted_count = int(is_enc.sum())
            if unencrypted_count > 0:
                anomalies.append(f"HIGH: {unencrypted_count} resources are currently unencrypted.")
                
        return anomalies

    def generate_outputs(self, df: pd.DataFrame, results: Dict):
        with open('audit_report.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        
        with open('executive_summary.md', 'w', encoding='utf-8') as f:
            f.write("# Infrastructure Audit Summary\n\n")
            f.write(f"- **Total Waste Identified:** ${results['total_waste']:,.2f}\n")
            f.write(f"- **Security Flags:** {len(results['anomalies'])}\n\n")
            if results['anomalies']:
                f.write("### Security Notices\n")
                for anomaly in results['anomalies']:
                    f.write(f"- {anomaly}\n")
            f.write("\n---\n*Generated by AWS FinOps Auditor*\n")

    def run_pipeline(self, df: pd.DataFrame) -> Dict:
        df = self.process_data(df)
        waste = self.calculate_waste(df)
        anomalies = self.detect_security_anomalies(df)
        
        results = {
            "total_waste": round(waste, 2),
            "anomalies": anomalies,
            "records_analyzed": len(df)
        }
        
        self.generate_outputs(df, results)
        return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AWS FinOps Auditor")
    parser.add_argument('--file', type=str, required=True, help="Path to AWS usage CSV file")
    parser.add_argument('--remediate', action='store_true', help="Generate executable script to delete wasted resources (Enterprise)")
    parser.add_argument('--compliance', action='store_true', help="Export SOC2/ISO27001 audit evidence CSV (Enterprise)")
    args = parser.parse_args()
    
    auditor = InfrastructureAuditor()
    try:
        raw_df = pd.read_csv(args.file)
        print(f"Scanning {args.file} ({len(raw_df)} records)...")
        
        # Pass a copy to the main pipeline so it can anonymize IDs safely
        results = auditor.run_pipeline(raw_df.copy())
        
        print(f"\nAudit Complete!")
        print(f"==========================================")
        print(f"Records Analyzed:       {results['records_analyzed']}")
        print(f"Total Waste Identified: ${results['total_waste']:,.2f}")
        print(f"Security Flags:         {len(results['anomalies'])}")
        print(f"==========================================")
        print("Generated 'audit_report.json' and 'executive_summary.md'.")
        
        # Enterprise triggers utilizing the raw dataframe (real resource IDs)
        if args.remediate:
            print("\n[Enterprise Feature] Triggering automated remediation generator...")
            generate_remediation_script(raw_df, "remediate_anomalies.sh")
            
        if args.compliance:
            print("\n[Enterprise Feature] Triggering SOC2/ISO27001 audit exporter...")
            generate_compliance_report(raw_df)
            
    except Exception as e:
        print(f"\n[!] Audit Failed: {e}", file=sys.stderr)
        sys.exit(1)