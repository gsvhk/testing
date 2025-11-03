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

# ========================================
# EXPANDED KEYBOOK - Component Utilization
# ========================================
KEYBOOK = {
    # === Core Components ===
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

    # === Windows Services (Expanded) ===
    "Alljoyn router service": "Disabled",
    "AllJoyn Router Service": "Disabled",
    "App Readiness": "Disabled",
    "Application Identity": "Disabled",
    "Application Layer Gateway Service": "Disabled",
    "Application Information": "Disabled",
    "Application Management": "Disabled",
    "AppX Deployment Service (AppXSVC)": "Disabled",
    "Assigned Access Manager Service": "Disabled",
    "AtherosSvc": "Running",
    "Auto Time Zone Updater": "Disabled",
    "AVCTP service": "Disabled",
    "Background Intelligent Transfer Service": "Disabled",
    "Background Tasks Infrastructure Service": "Running",
    "Base Filtering Engine": "Running",
    "BitLocker Drive Encryption Service": "Disabled",
    "Block Level Backup Engine Service": "Disabled",
    "Bluetooth Audio Gateway Service": "Disabled",
    "Bluetooth Support Service": "Disabled",
    "Bluetooth User Support Service": "Disabled",
    "BranchCache": "Disabled",
    "Capability Access Manager Service": "Disabled",
    "CaptureService": "Disabled",
    "Certificate Propagation": "Disabled",
    "Client License Service (ClipSVC)": "Disabled",
    "Clipboard User Service": "Disabled",
    "CNG Key Isolation": "Disabled",
    "COM+ Event System": "Running",
    "COM+ System Application": "Disabled",
    "Connected Devices Platform Service": "Running",
    "Connected Devices Platform User Service": "Running",
    "Connected User Experiences and Telemetry": "Disabled",
    "ConsentUX": "Disabled",
    "Contact Data": "Disabled",
    "CoreMessaging": "Running",
    "Credential Manager": "Disabled",
    "Cryptographic Services": "Running",
    "Data Sharing Service": "Disabled",
    "Data Usage": "Running",
    "DCOM Server Process Launcher": "Running",
    "Delivery Optimization": "Disabled",
    "Device Association Service": "Disabled",
    "Device Install Service": "Disabled",
    "Device Management Enrollment Service": "Disabled",
    "Device Management Wireless Application Protocol": "Disabled",
    "Device Setup Manager": "Disabled",
    "DevicePicker": "Disabled",
    "DevicesFlow": "Disabled",
    "DevQuery Background Discovery Broker": "Disabled",
    "DHCP Client": "Running",
    "Diagnostic Execution Service": "Disabled",
    "Diagnostic Policy Service": "Running",
    "Diagnostic Service Host": "Disabled",
    "Diagnostic System Host": "Disabled",
    "Display Enhancement Service": "Disabled",
    "Distributed Link Tracking Client": "Running",
    "Distributed Transaction Coordinator": "Disabled",
    "DNS Client": "Running",
    "Downloaded Maps Manager": "Disabled",
    "Embedded Mode": "Disabled",
    "Encrypting File System (EFS)": "Disabled",
    "Enterprise App Management Service": "Disabled",
    "Extensible Authentication Protocol": "Disabled",
    "Fax": "Disabled",
    "File History Service": "Disabled",
    "Function Discovery Provider Host": "Disabled",
    "Function Discovery Resource Publication": "Disabled",
    "GameDVR and Broadcast User Service": "Disabled",
    "Geolocation Service": "Disabled",
    "GraphicsPerfSvc": "Disabled",
    "Group Policy Client": "Disabled",
    "Human Interface Device Service": "Disabled",
    "HV Host Service": "Disabled",
    "Hyper-V Data Exchange Service": "Disabled",
    "Hyper-V Guest Service Interface": "Disabled",
    "Hyper-V Guest Shutdown Service": "Disabled",
    "Hyper-V Heartbeat Service": "Disabled",
    "Hyper-V PowerShell Direct Service": "Disabled",
    "Hyper-V Remote Desktop Virtualization Service": "Disabled",
    "Hyper-V Time Synchronization Service": "Disabled",
    "Hyper-V Volume Shadow Copy Requestor": "Disabled",
    "IKE and AuthIP IPsec Keying Modules": "Running",
    "Infrared monitor service": "Disabled",
    "Intel(R) Capability Licensing Service TCP IP Interface": "Disabled",
    "Intel(R) Content Protection HDCP Service": "Running",
    "Intel(R) Content Protection HECI Service": "Disabled",
    "Intel(R) Dynamic Application Loader Host Interface": "Disabled",
    "Intel(R) HD Graphics Control Panel Service": "Running",
    "Internet Connection Sharing (ICS)": "Disabled",
    "IP Helper": "Running",
    "IP Translation Configuration Service": "Disabled",
    "IPsec Policy Agent": "Disabled",
    "KtmRm for Distributed Transaction Coordinator": "Disabled",
    "Language Experience Service": "Disabled",
    "Link-Layer Topology Discovery Mapper": "Disabled",
    "Local Profile Assistant Service": "Disabled",
    "Local Session Manager": "Running",
    "Messaging Service": "Disabled",
    "Microsoft (R) Diagnostics Hub Standard Collector Service": "Disabled",
    "Microsoft Account Sign-in Assistant": "Disabled",
    "Microsoft App-V Client": "Disabled",
    "Microsoft Defender Core Service": "Disabled",
    "Microsoft Edge Elevation Service": "Disabled",
    "Microsoft Edge Update Service": "Disabled",
    "Microsoft iSCSI Initiator Service": "Disabled",
    "Microsoft passport": "Disabled",
    "Microsoft passport Container": "Disabled",
    "Microsoft Software Shadow Copy Provider": "Disabled",
    "Microsoft Storage Spaces SMP": "Disabled",
    "Microsoft Store Install Service": "Disabled",
    "Microsoft Windows SMS Router Service": "Disabled",
    "ModaMonitor Management": "Disabled",
    "ModaSecure Access": "Disabled",
    "Natural Authentication": "Disabled",
    "Net.TCP Port Sharing Service": "Disabled",
    "Netlogon": "Disabled",
    "Network Connected Devices Auto-Setup": "Disabled",
    "Network Connection Broker": "Disabled",
    "Network Connections": "Disabled",
    "Network Connectivity Assistant": "Disabled",
    "Network List Service": "Disabled",
    "DCMTK": "Running",
    "Network Setup Service": "Disabled",
    "Network Storage Interface Service": "Running",
    "Offline Files": "Disabled",
    "OpenSSH Authentication Agent": "Disabled",
    "Optimize Drives": "Disabled",
    "Parental Controls": "Disabled",
    "Payments and NFC/SE Manager": "Disabled",
    "Peer Name Resolution Protocol": "Disabled",
    "Peer Networking Grouping": "Disabled",
    "Peer Networking Identity Manager": "Disabled",
    "Performance Counter DLL Host": "Disabled",
    "Performance Logs and Alerts": "Disabled",
    "Phone Service": "Disabled",
    "Plug and Play": "Disabled",
    "PNRP Machine Name Publication Service": "Disabled",
    "Portable Device Enumerator Service": "Disabled",
    "Power": "Running",
    "Printer Extensions and Notifications": "Disabled",
    "PrintWorkflow": "Disabled",
    "Problem Reports and Solutions Control Panel Support": "Disabled",
    "Program Compatibility Assistant Service": "Disabled",
    "Qualcomm Atheros WLAN Driver Service": "Running",
    "Quality Windows Audio Video Experience": "Disabled",
    "Radio Management Service": "Disabled",
    "Remote Access Auto Connection Manager": "Disabled",
    "Remote Access Connection Manager": "Running",
    "Remote Desktop Configuration": "Disabled",
    "Remote Desktop Services UserMode Port Redirector": "Disabled",
    "Remote Procedure Call (RPC)": "Running",
    "Remote Procedure Call (RPC) Locator": "Disabled",
    "Remote Registry": "Disabled",
    "Retail Demo Service": "Disabled",
    "Routing and Remote Access": "Disabled",
    "RPC Endpoint Mapper": "Running",
    "Secondary Logon": "Disabled",
    "Secure Socket Tunneling Protocol Service": "Disabled",
    "Security Accounts Manager": "Running",
    "Security Center": "Disabled",
    "Sensor Data Service": "Disabled",
    "Sensor Monitoring Service": "Disabled",
    "Sensor Service": "Disabled",
    "Sentinel LDK License Manager": "Running",
    "Server": "Running",
    "Shared PC Account Manager": "Disabled",
    "Shell Hardware Detection": "Running",
    "Smart Card": "Disabled",
    "Smart Card Device Enumeration Service": "Disabled",
    "Smart Card Removal Policy": "Disabled",
    "SNMP Trap": "Disabled",
    "Software Protection": "Disabled",
    "Spatial Data Service": "Disabled",
    "Spot Verifier": "Disabled",
    "SSDP Discovery": "Disabled",
    "State Repository Service": "Disabled",
    "Still Image Acquisition Events": "Disabled",
    "Storage Service": "Disabled",
    "Storage Tiers Management": "Disabled",
    "Symantec Endpoint Protection": "Running",
    "Symantec Endpoint Protection Local Proxy Service": "Disabled",
    "Symantec Endpoint Protection WSC Service": "Running",
    "Symantec Network Access Control": "Disabled",
    "Sync Host": "Disabled",
    "SysMain": "Disabled",
    "System Event Notification Service": "Running",
    "System Events Broker": "Running",
    "System Guard Runtime Monitor Broker": "Disabled",
    "Task Scheduler": "Running",
    "TCP/IP NetBIOS Helper": "Disabled",
    "Telephony": "Disabled",
    "TestComplete 14 Service": "Running",
    "Themes": "Running",
    "Time Broker": "Disabled",
    "Touch Keyboard and Handwriting Panel Service": "Running",
    "Update Orchestrator Service": "Disabled",
    "UPnP Device Host": "Disabled",
    "User Data Access": "Disabled",
    "User Data Storage": "Disabled",
    "User Experience Virtualization Service": "Disabled",
    "User Manager": "Running",
    "User Profile Service": "Running",
    "Virtual Disk": "Disabled",
    "Volume Shadow Copy": "Disabled",
    "Volumetric Audio Compositor Service": "Disabled",
    "WalletService": "Disabled",
    "WarpJITSvc": "Disabled",
    "Web Account Manager": "Disabled",
    "WebClient": "Disabled",
    "Wi-Fi Direct Services Connection Manager Service": "Disabled",
    "Windows Audio": "Running",
    "Windows Audio Endpoint Builder": "Running",
    "Windows Backup": "Disabled",
    "Windows Biometric Service": "Disabled",
    "Windows Camera Frame Server": "Disabled",
    "Windows Connect Now - Config Registrar": "Disabled",
    "Windows Connection Manager": "Running",
    "Windows Defender Advanced Threat Protection Service": "Disabled",
    "Windows Defender Antivirus Network Inspection Service": "Disabled",
    "Windows Defender Antivirus Service": "Disabled",
    "Windows Defender Firewall": "Running",
    "Windows Encryption Provider Host Service": "Disabled",
    "Windows Error Reporting Service": "Disabled",
    "Windows Event Collector": "Disabled",
    "Windows Event Log": "Running",
    "Windows Font Cache Service": "Running",
    "Windows Image Acquisition (WIA)": "Disabled",
    "Windows Insider Service": "Disabled",
    "Windows Installer": "Disabled",
    "Windows License Manager Service": "Disabled",
    "Windows Management Instrumentation": "Running",
    "Windows Management Service": "Disabled",
    "Windows Media Player Network Sharing Service": "Disabled",
    "Windows Mobile Hotspot Service": "Disabled",
    "Windows Modules Installer": "Disabled",
    "Windows Perception Service": "Disabled",
    "Windows Perception Simulation Service": "Disabled",
    "Windows Push Notifications System Service": "Running",
    "Windows Push Notifications User Service": "Running",
    "Windows Push ToInstall Service": "Disabled",
    "Windows Remote Management (WS-Management)": "Disabled",
    "Windows Search": "Disabled",
    "Windows Update Medic Service": "Disabled",
    "WinHTTP Web Proxy Auto-Discovery Service": "Disabled",
    "Wired AutoConfig": "Disabled",
    "WLAN AutoConfig": "Running",
    "WMI Performance Adapter": "Disabled",
    "Work Folders": "Disabled",
    "Workstation": "Disabled",
    "WWAN AutoConfig": "Running",
    "Xbox Accessory Management Service": "Disabled",
    "Xbox Live Auth Manager": "Disabled",
    "Xbox Live Game Save": "Disabled",
    "Xbox Live Networking Service": "Disabled",

    # === Drivers ===
    "Cloud Files Mini Filter Driver": "Running",
    "Common Log File System Driver": "Running",
    "Streaming WOW Thunk Service Driver": "Running",
    "Partition Management Driver": "Running",
    "ACPI Driver": "Running",
    "AcpiDev": "Stopped",
    "acpiex": "Running",
    "afunix": "Running",
    "ahcache": "Running",
    "bam": "Running",
    "Basic display": "Running",
    "Basic Render": "Running",
    "Beep": "Running",
    "BHDrvx64": "Running",
    "bowser": "Running",
    "cdrom": "Running",
    "CldFlt": "Running",
    "CLFS": "Running",
    "CNG": "Running",
    "CSC": "Running",
    "Dfsc": "Running",
    "Disk": "Running",
    "DXGKrnl": "Running",
    "FileCrypt": "Running",
    "FileInfo": "Running",
    "FltMgr": "Running",
    "fvevol": "Running",
    "GpuEnergyDrv": "Running",
    "HTTP": "Running",
    "IDSVia64": "Running",
    "intelpep": "Running",
    "iorate": "Running",
    "KSecDD": "Running",
    "KSecPKG": "Running",
    "lltdio": "Running",
    "luafv": "Running",
    "MMCSS": "Running",
    "mountmgr": "Running",
    "mpsdrv": "Running",
    "mrxsmb": "Running",
    "mrxsmb20": "Running",
    "Msfs": "Running",
    "msisadrv": "Running",
    "MsSecCore": "Running",
    "mssmbios": "Running",
    "MTConfig": "Running",
    "Mup": "Running",
    "NativeWifiP": "Running",
    "NDIS": "Running",
    "Ndisuio": "Running",
    "Ndu": "Running",
    "NetBios": "Running",
    "NetBT": "Running",
    "Npfs": "Running",
    "npsvctrig": "Running",
    "nsiproxy": "Running",
    "Null": "Running",
    "pci": "Running",
    "pcw": "Running",
    "pdc": "Running",
    "PEAUTH": "Running",
    "Psched": "Running",
    "rdbss": "Running",
    "rdyboost": "Running",
    "rspndr": "Running",
    "SgrmAgent": "Running",
    "spacereport": "Running",
    "SRTSPX": "Running",
    "srv2": "Running",
    "srvnet": "Running",
    "storqosflt": "Running",
    "SymEFASI": "Running",
    "SymIRON": "Running",
    "SYMNETS": "Running",
    "SysPlant": "Running",
    "Tcpip": "Running",
    "tcpipreg": "Running",
    "tdx": "Running",
    "Teefer2": "Running",
    "vdrvroot": "Running",
    "volmgr": "Running",
    "volmgrx": "Running",
    "volume": "Running",
    "vwififlt": "Running",
    "wanarp": "Running",
    "wcifs": "Running",
    "wdf01000WFPLWFS": "Running",
    "WindowsTrust": "Running",
    "WinQuic": "Running",
    "Wof": "Running",
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
            max-width: 900px;
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
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 15px;
            border-radius: 8px;
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🏥 Medical Device CVE Assessment Tool</h1>
        <p class="subtitle">Automated Vulnerability Assessment for Medical Products</p>
        
        <div class="info-box">
            <p><strong>📋 Instructions:</strong></p>
            <p>• Enter CVE IDs manually (comma-separated) or upload an Excel file</p>
            <p>• Select the product to assess (currently: MC-1)</p>
            <p>• Click "Generate Assessment" to create the report</p>
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
                            📁 Click to select Excel file
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
            document.getElementById('fileLabel').innerHTML = '📁 ' + fileName;
        });

        document.getElementById('assessmentForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const error = document.getElementById('error');
            
            // Hide previous results
            result.style.display = 'none';
            error.style.display = 'none';
            
            // Show loading
            submitBtn.disabled = true;
            loading.style.display = 'block';
            
            try {
                const response = await fetch('/assess', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    result.innerHTML = `
                        <strong>✅ Assessment Complete!</strong><br>
                        Processed ${data.cve_count} CVE(s) for product ${data.product}<br>
                        <a href="/download/${data.filename}" style="color: #155724; text-decoration: underline;">
                            📥 Download Assessment Report (Excel)
                        </a>
                    `;
                    result.style.display = 'block';
                } else {
                    error.innerHTML = `<strong>❌ Error:</strong> ${data.error}`;
                    error.style.display = 'block';
                }
            } catch (err) {
                error.innerHTML = `<strong>❌ Error:</strong> ${err.message}`;
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

def fetch_cve_from_nvd(cve_id):
    """Fetch CVE details from NVD API"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        time.sleep(0.6)  # Rate limiting: NVD allows ~5 requests per 30 seconds
        
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]['cve']
                
                # Extract details
                description = vuln.get('descriptions', [{}])[0].get('value', 'No description available')
                
                # Get CVSS metrics
                metrics = vuln.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else metrics.get('cvssMetricV30', [{}])[0] if 'cvssMetricV30' in metrics else {}
                
                cvss_data = cvss_v3.get('cvssData', {})
                attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                base_score = cvss_data.get('baseScore', 'N/A')
                base_severity = cvss_data.get('baseSeverity', 'N/A')
                
                return {
                    'cve_id': cve_id,
                    'description': description,
                    'attack_vector': attack_vector,
                    'user_interaction': user_interaction,
                    'cvss_score': base_score,
                    'severity': base_severity,
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
        
        return None
    except Exception as e:
        print(f"Error fetching {cve_id}: {str(e)}")
        return None

def extract_affected_component(description):
    """Extract potential affected component from CVE description"""
    description_lower = description.lower()
    
    # Component keywords to search for (expanded list)
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
    """
    Generate assessment based on CVE data and keybook
    PRIORITY: Check keybook FIRST, then attack vector
    """
    assessment = ""
    impact_status = "Not Impacted"
    
    component = extract_affected_component(cve_data['description'])
    attack_vector = cve_data['attack_vector']
    user_interaction = cve_data['user_interaction']
    
    # Check if component is in keybook
    component_status = KEYBOOK.get(component, None)
    
    # PRIORITY 1: Check if component is disabled/not used in keybook
    if component_status and component_status.lower() in ['not used', 'disabled', 'not installed', 'not configured', 'stopped']:
        assessment = (
            f"By exploiting the vulnerability, an attacker with local access needs to "
            f"send a specially crafted input to the system. Due to a flaw in the {component}, "
            f"it triggers an integer overflow or wraparound condition, leading to a local privilege escalation vulnerability.\n\n"
            f"However, {component} is not used in this device and feature also disabled.\n\n"
            f"Based on the above justification this item is not applicable."
        )
    
    # PRIORITY 2: Check attack vector if component is running/enabled
    elif attack_vector == "LOCAL":
        assessment = (
            f"By exploiting the vulnerability, an attacker with local access needs to "
            f"execute malicious code on the system. Due to a flaw in {component}, "
            f"this could lead to privilege escalation or information disclosure.\n\n"
            f"However, device placed in secure location and it's configuration does not allow "
            f"for local execution of untrusted applications.\n\n"
            f"Based on the above justification, this item is not applicable."
        )
    
    # PRIORITY 3: Check if user interaction is required
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
    
    # PRIORITY 4: Default network-based attack
    else:
        assessment = (
            f"By exploiting the vulnerability, an attacker could leverage a flaw in {component} "
            f"via network access. This could lead to remote code execution or information disclosure.\n\n"
            f"However, the device is deployed in a controlled network environment "
            f"with appropriate security controls in place.\n\n"
            f"Based on the above justification, this item is not applicable."
        )
    
    # Add reference
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
        
        # Get CVEs from manual input
        manual_input = request.form.get('cve_manual', '').strip()
        if manual_input:
            cve_ids.extend([cve.strip() for cve in manual_input.split(',') if cve.strip()])
        
        # Get CVEs from file upload
        if 'cve_file' in request.files:
            file = request.files['cve_file']
            if file and file.filename:
                df = pd.read_excel(file)
                # Look for CVE column (case-insensitive)
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
        
        # Remove duplicates
        cve_ids = list(set(cve_ids))
        
        # Fetch CVE data and generate assessments
        results = []
        for cve_id in cve_ids:
            cve_data = fetch_cve_from_nvd(cve_id)
            if cve_data:
                impact_status, assessment = generate_assessment(cve_data, product)
                results.append({
                    'Vulnerability No': cve_data['cve_id'],
                    'Impacted / Not Impact': impact_status,
                    'Yes / No': 'No',
                    'Assessment': assessment
                })
            else:
                results.append({
                    'Vulnerability No': cve_id,
                    'Impacted / Not Impact': 'Data Not Available',
                    'Yes / No': 'N/A',
                    'Assessment': f'Unable to fetch CVE data from NVD. Please verify CVE ID.\n\nReference: https://nvd.nist.gov/vuln/detail/{cve_id}'
                })
        
        # Create Excel file with proper formatting
        df = pd.DataFrame(results)
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'CVE_Assessment_{product}_{timestamp}.xlsx'
        
        # Save to BytesIO with formatting
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Assessment')
            
            # Format the worksheet
            worksheet = writer.sheets['Assessment']
            
            # Set column widths
            worksheet.column_dimensions['A'].width = 20  # Vulnerability No
            worksheet.column_dimensions['B'].width = 20  # Impacted / Not Impact
            worksheet.column_dimensions['C'].width = 12  # Yes / No
            worksheet.column_dimensions['D'].width = 100 # Assessment
            
            # Apply text wrapping and alignment to all cells
            for row in worksheet.iter_rows(min_row=1, max_row=len(df)+1):
                for cell in row:
                    cell.alignment = Alignment(
                        wrap_text=True,
                        vertical='top',
                        horizontal='left'
                    )
            
            # Set row heights for better readability
            for row_num in range(2, len(df) + 2):  # Start from row 2 (after header)
                worksheet.row_dimensions[row_num].height = None  # Auto-adjust height
        
        output.seek(0)
        
        # Store in memory (in production, use proper storage)
        if not hasattr(app, 'reports'):
            app.reports = {}
        app.reports[filename] = output.getvalue()
        
        return jsonify({
            'success': True,
            'filename': filename,
            'cve_count': len(cve_ids),
            'product': product
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
