import pandas as pd
from datetime import datetime

def generate_compliance_report(df: pd.DataFrame, output_file: str = "compliance_audit_export.csv"):
    """
    Maps infrastructure anomalies to standard compliance frameworks (SOC2, ISO27001).
    """
    compliance_records = []
    
    # Normalize columns to lowercase to handle varying AWS export formats
    df_norm = df.rename(columns={c: str(c).strip().lower() for c in df.columns})
    
    # 1. Check for unencrypted resources (SOC2 CC6.6 / ISO27001 A.10.1.1)
    if 'is_encrypted' in df_norm.columns:
        unencrypted = df_norm[df_norm['is_encrypted'].astype(str).str.strip().str.lower().isin(['false', '0', 'no', 'f'])]
        for _, row in unencrypted.iterrows():
            compliance_records.append({
                'Resource_ID': row.get('resource_id', 'Unknown'),
                'Violation_Type': 'Unencrypted Data at Rest',
                'Framework_Control': 'SOC2 CC6.6, ISO27001 A.10.1.1',
                'Severity': 'HIGH',
                'Status': 'FAILED'
            })

    # 2. Check for public IP exposure (SOC2 CC6.1 / ISO27001 A.13.1.1)
    if 'is_public' in df_norm.columns:
        public_exposed = df_norm[df_norm['is_public'].astype(str).str.strip().str.lower().isin(['true', '1', 'yes', 't'])]
        for _, row in public_exposed.iterrows():
            compliance_records.append({
                'Resource_ID': row.get('resource_id', 'Unknown'),
                'Violation_Type': 'Public Internet Exposure',
                'Framework_Control': 'SOC2 CC6.1, ISO27001 A.13.1.1',
                'Severity': 'CRITICAL',
                'Status': 'FAILED'
            })
    
    # Generate the DataFrame and export as CSV evidence
    if compliance_records:
        comp_df = pd.DataFrame(compliance_records)
        comp_df['Audit_Date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Reorder columns for auditor readability
        columns_order = ['Audit_Date', 'Resource_ID', 'Violation_Type', 'Framework_Control', 'Severity', 'Status']
        comp_df = comp_df[columns_order]
        
        comp_df.to_csv(output_file, index=False)
        print(f"[Enterprise] Compliance export generated: '{output_file}' with {len(comp_df)} violations flagged.")
    else:
        print("[Enterprise] No compliance violations detected. Audit export skipped.")