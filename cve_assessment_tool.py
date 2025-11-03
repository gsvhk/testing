"""
Medical Device Vulnerability Assessment Tool
Automates CVE assessment for medical products using NVD data
"""

from flask import Flask, render_template_string, request, send_file, jsonify
import requests
import pandas as pd
from datetime import datetime
import time
import io
import re
from openpyxl.styles import Alignment

app = Flask(__name__)

# Keybook data - Component usage (EXPANDED)
KEYBOOK = {
    "Mail": "Not used",
    "MS office": "Not used",
    "MS Office": "Not used",
    "IPv6": "Disabled",
    "SMB": "Disabled",
    "SMBv1": "Disabled",
    "MSMQ Feature": "Disabled",
    "Secure Boot": "Enabled",
    "AMD Processor": "Not used",
    "Bluetooth driver": "Disabled",
    "Bluetooth": "Disabled",
    "Printer Driver": "Not installed",
    "iSCSI Service protocol": "Not used",
    "iSCSI": "Not used",
    "Routing and Remote Access service": "Disabled",
    "Internet Key Exchange protocol": "Not used",
    "SSTP service": "Not used",
    "WDAC OLE DB": "Not used",
    "PEAP Authentication": "Not used",
    "PPTP protocol": "Not configured",
    "ODBC Driver": "Not used",
    "ODBC": "Not used",
    "PostScript and PCL6 class printer driver": "Not used",
    "PPPoE protocol": "Not configured",
    "Broadband Driver": "Not used",
    "Network Virtualization": "Not used",
    "Hyper-V": "Disabled",
    "Hyper-V component": "Disabled",
    "Windows Hyper-V": "Disabled",
    "Windows Hyper-V component": "Disabled",
    "Remote Management Service": "Disabled",
    "Line Printer Daemon Service": "Not used",
    "PowerShell": "Running",
    "File Explorer": "Running",
    "Windows File Explorer": "Running",
    "Windows Imaging Component": "Running",
    "Graphics Component": "Running",
    "Microsoft Graphics Component": "Running",
    "Desktop Window Manager": "Running",
    "Windows Desktop Window Manager": "Running",
    "Windows Kernel": "Running",
    "Print Spooler": "Running",
    "Remote Desktop": "Disabled",
    "Remote Desktop Services": "Disabled",
    "NTFS": "Disabled",
    "Windows Time": "Disabled",
    "Windows Update": "Disabled",
    "USB Generic Parent Driver": "Stopped",
    "Mobile Broadband Driver": "Not installed",
    "Wi-Fi Driver": "Running",
    "Windows Layer-2 Bridge Network Driver": "Not installed",
    "Tcpip": "Running",
    "TCP/IP": "Running",
    "IPv4": "Running",
    "LDAP": "enabled/not running",
    "ActiveX": "Disabled",
    "Adobe Acrobat": "Running",
    "WLAN": "Running",
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Medical Device CVE Assessment Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-section {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        select, input[type="text"], textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        select:focus, input:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        textarea {
            resize: vertical;
            min-height: 100px;
            font-family: 'Courier New', monospace;
        }
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            width: 100%;
        }
        .file-input-wrapper input[type=file] {
            position: absolute;
            left: -9999px;
        }
        .file-input-label {
            display: block;
            padding: 12px;
            background: white;
            border: 2px dashed #667eea;
            border-radius: 8px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        .file-input-label:hover {
            background: #f0f0ff;
            border-color: #764ba2;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .result {
            display: none;
            margin-top: 20px;
        }
        .error {
            display: none;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            color: #721c24;
        }
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .info-box p {
            margin: 5px 0;
            font-size: 13px;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background-color: #f2f2f2;
            font-weight: 600;
        }
        .assessment-text {
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
        }
        .download-section {
            text-align: center;
            margin: 30px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Medical Device CVE Assessment Tool</h1>
        <p class="subtitle">Automated Vulnerability Assessment for Medical Products</p>
        
        <div class="info-box">
            <p><strong>Instructions:</strong></p>
            <p>• Enter CVE IDs manually (comma-separated) or upload an Excel file</p>
            <p>• Select the product to assess (currently: MC-1)</p>
            <p>• Click "Generate Assessment" to preview and download the report</p>
        </div>

        <form id="assessmentForm" enctype="multipart/form-data">
            <div class="form-section">
                <div class="form-group">
                    <label for="product">Select Product:</label>
                    <select id="product" name="product" required>
                        <option value="MC-1">MC-1 (Medical Device)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="cve_manual">Enter CVE IDs (comma-separated):</label>
                    <textarea id="cve_manual" name="cve_manual" placeholder="Example: CVE-2025-49734, CVE-2025-50154, CVE-2025-53799"></textarea>
                </div>

                <div class="form-group">
                    <label>OR Upload Excel File with CVE Column:</label>
                    <div class="file-input-wrapper">
                        <input type="file" id="cve_file" name="cve_file" accept=".xlsx,.xls">
                        <label for="cve_file" class="file-input-label" id="fileLabel">
                            Click to select Excel file
                        </label>
                    </div>
                </div>

                <button type="submit" class="btn" id="submitBtn">Generate Assessment Report</button>
            </div>
        </form>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px; color: #666;">Fetching CVE data from NVD and generating assessment...</p>
        </div>

        <div class="result" id="result"></div>
        <div class="error" id="error"></div>
    </div>

    <script>
        document.getElementById('cve_file').addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Click to select Excel file';
            document.getElementById('fileLabel').innerHTML = ' ' + fileName;
        });

        document.getElementById('assessmentForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const error = document.getElementById('error');
            
            result.style.display = 'none';
            error.style.display = 'none';
            
            submitBtn.disabled = true;
            loading.style.display = 'block';
            
            try {
                const response = await fetch('/assess', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    let tableHTML = `
                        <h3 style="margin-bottom: 15px; color: #333;">Assessment Preview</h3>
                        <p><strong>Product:</strong> ${data.product} | <strong>CVEs Processed:</strong> ${data.cve_count}</p>
                        <table>
                            <thead>
                                <tr>
                                    <th>Vulnerability No</th>
                                    <th>Impacted / Not Impact</th>
                                    <th>Assessment</th>
                                </tr>
                            </thead>
                            <tbody>
                    `;

                    data.results.forEach(row => {
                        tableHTML += `
                            <tr>
                                <td><a href="https://nvd.nist.gov/vuln/detail/${row['Vulnerability No']}" target="_blank">${row['Vulnerability No']}</a></td>
                                <td>${row['Impacted / Not Impact']}</td>
                                <td class="assessment-text">${row['Assessment'].replace(/\\n/g, '<br>')}</td>
                            </tr>
                        `;
                    });

                    tableHTML += `
                            </tbody>
                        </table>
                        <div class="download-section">
                            <button onclick="window.location.href='/download/${data.filename}'" class="btn" style="width: auto; display: inline-block; padding: 12px 30px;">
                                Download Excel Report
                            </button>
                        </div>
                    `;

                    result.innerHTML = tableHTML;
                    result.style.display = 'block';
                } else {
                    error.innerHTML = `<strong>Error:</strong> ${data.error}`;
                    error.style.display = 'block';
                }
            } catch (err) {
                error.innerHTML = `<strong>Error:</strong> ${err.message}`;
                error.style.display = 'block';
            } finally {
                submitBtn.disabled = false;
                loading.style.display = 'none';
            }
        });
    </script>
</body>
</html>
"""

# [Rest of your functions: fetch_cve_from_nvd, extract_affected_component, generate_assessment — UNCHANGED]

def fetch_cve_from_nvd(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        time.sleep(0.6)
        
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]['cve']
                description = vuln.get('descriptions', [{}])[0].get('value', 'No description available')
                metrics = vuln.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else metrics.get('cvssMetricV30', [{}])[0] if 'cvssMetricV30' in metrics else {}
                cvss_data = cvss_v3.get('cvssData', {})
                return {
                    'cve_id': cve_id,
                    'description': description,
                    'attack_vector': cvss_data.get('attackVector', 'UNKNOWN'),
                    'user_interaction': cvss_data.get('userInteraction', 'UNKNOWN'),
                    'cvss_score': cvss_data.get('baseScore', 'N/A'),
                    'severity': cvss_data.get('baseSeverity', 'N/A'),
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
        return None
    except Exception as e:
        print(f"Error fetching {cve_id}: {str(e)}")
        return None

def extract_affected_component(description):
    description_lower = description.lower()
    component_keywords = {
        'PowerShell': ['powershell', 'power shell'],
        'File Explorer': ['file explorer', 'windows explorer', 'explorer.exe'],
        'Windows File Explorer': ['file explorer', 'windows explorer'],
        'Windows Imaging Component': ['imaging component', 'wic', 'windows imaging'],
        'Graphics Component': ['graphics component', 'graphics driver'],
        'Microsoft Graphics Component': ['microsoft graphics', 'graphics component'],
        'Desktop Window Manager': ['desktop window manager', 'dwm', 'dwm.exe'],
        'Windows Desktop Window Manager': ['desktop window manager', 'dwm'],
        'Windows Kernel': ['kernel', 'windows kernel', 'win32k'],
        'SMB': ['smb', 'server message block'],
        'SMBv1': ['smbv1', 'smb v1', 'smb version 1'],
        'Hyper-V': ['hyper-v', 'hypervisor', 'hyper-v component'],
        'Windows Hyper-V': ['hyper-v', 'hypervisor', 'windows hyper-v'],
        'Windows Hyper-V component': ['hyper-v component', 'hyper-v'],
        'Remote Desktop': ['remote desktop', 'rdp', 'terminal services'],
        'Remote Desktop Services': ['remote desktop services', 'terminal services'],
        'Print Spooler': ['print spooler', 'spooler', 'spoolsv'],
        'ODBC': ['odbc', 'odbc driver'],
        'ODBC Driver': ['odbc driver', 'odbc'],
        'iSCSI': ['iscsi', 'iscsi initiator'],
        'Bluetooth': ['bluetooth', 'bluetooth driver'],
        'USB': ['usb', 'universal serial bus'],
        'NTFS': ['ntfs', 'ntfs driver'],
        'TCP/IP': ['tcp/ip', 'tcpip', 'tcp protocol'],
        'IPv6': ['ipv6', 'internet protocol version 6'],
        'LDAP': ['ldap', 'lightweight directory'],
        'ActiveX': ['activex', 'active-x'],
        'Adobe Acrobat': ['adobe acrobat', 'acrobat reader'],
        'MS Office': ['microsoft office', 'ms office', 'office'],
    }
    for component, keywords in component_keywords.items():
        for keyword in keywords:
            if keyword in description_lower:
                return component
    return "Unknown Component"

def generate_assessment(cve_data, product):
    assessment = ""
    impact_status = "Not Impacted"
    component = extract_affected_component(cve_data['description'])
    attack_vector = cve_data['attack_vector']
    user_interaction = cve_data['user_interaction']
    component_status = KEYBOOK.get(component, None)

    if component_status and component_status.lower() in ['not used', 'disabled', 'not installed', 'not configured', 'stopped']:
        assessment = (
            f"By exploiting the vulnerability, an attacker with local access needs to "
            f"send a specially crafted input to the system. Due to a flaw in the {component}, "
            f"it triggers an integer overflow or wraparound condition, leading to a local privilege escalation vulnerability.\n\n"
            f"However, {component} is not used in this device and feature also disabled.\n\n"
            f"Based on the above justification this item is not applicable."
        )
    elif attack_vector == "LOCAL":
        assessment = (
            f"By exploiting the vulnerability, an attacker with local access needs to "
            f"execute malicious code on the system. Due to a flaw in {component}, "
            f"this could lead to privilege escalation or information disclosure.\n\n"
            f"However, device placed in secure location and it's configuration does not allow "
            f"for local execution of untrusted applications.\n\n"
            f"Based on the above justification, this item is not applicable."
        )
    elif user_interaction == "REQUIRED":
        assessment = (
            f"By exploiting the vulnerability, an attacker needs to send a specially crafted "
            f"file to the system over the network and convince user to open it. Due to a flaw "
            f"in {component}, it triggers the exposure of sensitive information and it leads "
            f"to a spoofing vulnerability.\n\n"
            f"However, to exploit this vulnerability user interaction is required, but device "
            f"is operated by authorized individuals.\n\n"
            f"Based on the above justification, this item is not applicable."
        )
    else:
        assessment = (
            f"By exploiting the vulnerability, an attacker could leverage a flaw in {component} "
            f"via network access. This could lead to remote code execution or information disclosure.\n\n"
            f"However, the device is deployed in a controlled network environment "
            f"with appropriate security controls in place.\n\n"
            f"Based on the above justification, this item is not applicable."
        )
    assessment += f"\n\nReference: {cve_data['url']}"
    return impact_status, assessment

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/assess', methods=['POST'])
def assess():
    try:
        cve_ids = []
        product = request.form.get('product', 'MC-1')
        manual_input = request.form.get('cve_manual', '').strip()
        if manual_input:
            cve_ids.extend([cve.strip() for cve in manual_input.split(',') if cve.strip()])
        
        if 'cve_file' in request.files:
            file = request.files['cve_file']
            if file and file.filename:
                df = pd.read_excel(file)
                cve_column = None
                for col in df.columns:
                    if 'cve' in col.lower():
                        cve_column = col
                        break
                if cve_column:
                    file_cves = df[cve_column].dropna().astype(str).tolist()
                    cve_ids.extend(file_cves)
        
        if not cve_ids:
            return jsonify({'success': False, 'error': 'No CVE IDs provided'})
        
        cve_ids = list(set(cve_ids))
        results = []
        for cve_id in cve_ids:
            cve_data = fetch_cve_from_nvd(cve_id)
            if cve_data:
                impact_status, assessment = generate_assessment(cve_data, product)
                results.append({
                    'Vulnerability No': cve_data['cve_id'],
                    'Impacted / Not Impact': impact_status,
                    #'Yes / No': 'No',
                    'Assessment': assessment
                })
            else:
                results.append({
                    'Vulnerability No': cve_id,
                    'Impacted / Not Impact': 'Data Not Available',
                   # 'Yes / No': 'N/A',
                    'Assessment': f'Unable to fetch CVE data from NVD. Please verify CVE ID.\n\nReference: https://nvd.nist.gov/vuln/detail/{cve_id}'
                })
        
        # Generate Excel in memory
        df = pd.DataFrame(results)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'CVE_Assessment_{product}_{timestamp}.xlsx'
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Assessment')
            worksheet = writer.sheets['Assessment']
            worksheet.column_dimensions['A'].width = 20
            worksheet.column_dimensions['B'].width = 20
            #worksheet.column_dimensions['C'].width = 12
            worksheet.column_dimensions['D'].width = 100
            for row in worksheet.iter_rows(min_row=1, max_row=len(df)+1):
                for cell in row:
                    cell.alignment = Alignment(wrap_text=True, vertical='top', horizontal='left')
        output.seek(0)
        
        if not hasattr(app, 'reports'):
            app.reports = {}
        app.reports[filename] = output.getvalue()
        
        return jsonify({
            'success': True,
            'filename': filename,
            'cve_count': len(cve_ids),
            'product': product,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download/<filename>')
def download(filename):
    if hasattr(app, 'reports') and filename in app.reports:
        return send_file(
            io.BytesIO(app.reports[filename]),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    return "File not found", 404

if __name__ == '__main__':
    print("=" * 60)
    print("Medical Device CVE Assessment Tool")
    print("=" * 60)
    print("Starting server...")
    print("Open your browser and go to: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)