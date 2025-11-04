import json
import pandas as pd
import os

def normalize_path(path):
    """Expands user and normalizes Windows-style paths."""
    return os.path.abspath(os.path.expanduser(path.strip().strip('"').strip("'")))

def main():
    # Step 1: Get Excel file path
    excel_path = input("Enter the full path to your Excel file with CVEs: ").strip()
    excel_path = normalize_path(excel_path)
    if not os.path.exists(excel_path):
        print(f"❌ Excel file not found at: {excel_path}")
        return
    
    # Step 2: Read CVEs from Excel
    try:
        df = pd.read_excel(excel_path)
        cve_list = df.iloc[:, 0].dropna().astype(str).str.strip().tolist()
        print(f"✅ Loaded {len(cve_list)} CVEs from Excel.")
    except Exception as e:
        print("❌ Error reading Excel file:", e)
        return

    # Step 3: Get BOM file path
    bom_path = input("Enter the full path to your Dependency-Track bom.json file: ").strip()
    bom_path = normalize_path(bom_path)
    if not os.path.exists(bom_path):
        print(f"❌ BOM file not found at: {bom_path}")
        return

    # Step 4: Load BOM JSON
    try:
        with open(bom_path, 'r', encoding='utf-8') as f:
            bom_data = json.load(f)
        vuln_section = bom_data.get("vulnerabilities", [])
        bom_cves = [v.get("id") for v in vuln_section if "id" in v]
        print(f"✅ Found {len(bom_cves)} CVEs in BOM file.")
    except Exception as e:
        print("❌ Error reading BOM JSON:", e)
        return

    # Step 5: Compare CVEs
    missing_cves = [cve for cve in cve_list if cve not in bom_cves]
    found_cves = [cve for cve in cve_list if cve in bom_cves]

    print("\n🔍 Comparison Results:")
    print(f"✅ Found {len(found_cves)} CVEs in BOM.")
    print(f"❌ Missing {len(missing_cves)} CVEs in BOM.\n")

    if missing_cves:
        print("❌ Missing CVEs:")
        for cve in missing_cves:
            print(f"   - {cve}")
    else:
        print("🎉 All CVEs from Excel are present in the BOM file!")

if __name__ == "__main__":
    main()
