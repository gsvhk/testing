"""
Custom Dependency-Track Dashboard - COMPLETE VERSION
Save as: app.py
"""

from flask import Flask, render_template, request, jsonify, send_file
import requests
import sqlite3
import pandas as pd
from datetime import datetime
import json
import io
import traceback
import os
import time
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Enable CORS for development
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    return response

# ========================
# DATABASE SETUP
# ========================

def init_db():
    """Initialize SQLite database with tables"""
    try:
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        # Projects table
        c.execute('''CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT,
            dt_project_id TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Components table
        c.execute('''CREATE TABLE IF NOT EXISTS components (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            name TEXT NOT NULL,
            version TEXT,
            dt_component_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )''')
        
        # Vulnerabilities table
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            component_id TEXT,
            project_id TEXT,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            attack_vector TEXT,
            user_interaction TEXT,
            published_date TEXT,
            source TEXT DEFAULT 'DT',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (component_id) REFERENCES components(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )''')
        
        # Create index for better performance
        c.execute('''CREATE INDEX IF NOT EXISTS idx_vuln_cve_id ON vulnerabilities(cve_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_vuln_component_id ON vulnerabilities(component_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_vuln_project_id ON vulnerabilities(project_id)''')
        
        # Assessments table
        c.execute('''CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER,
            cve_id TEXT NOT NULL,
            status TEXT CHECK(status IN ('Affected', 'Not Affected', 'Under Review')) DEFAULT 'Under Review',
            assessment_text TEXT,
            assessed_by TEXT,
            assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )''')
        
        # Create index for assessments
        c.execute('''CREATE INDEX IF NOT EXISTS idx_assess_cve_id ON assessments(cve_id)''')
        
        # Audit log table for compliance
        c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id TEXT,
            user TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        traceback.print_exc()
        return False

def log_audit(action, entity_type, entity_id, user, details):
    """Log actions for compliance"""
    try:
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO audit_log (action, entity_type, entity_id, user, details)
                     VALUES (?, ?, ?, ?, ?)''',
                  (action, entity_type, entity_id, user, json.dumps(details)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ Audit log error: {e}")

# ========================
# DEPENDENCY-TRACK API
# ========================

class DependencyTrackAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-Api-Key': api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def test_connection(self):
        """Test if DT is reachable"""
        try:
            response = requests.get(
                f"{self.base_url}/api/version",
                headers=self.headers,
                timeout=10,
                verify=False
            )
            print(f"Connection test status: {response.status_code}")
            if response.status_code == 200:
                version_info = response.json()
                print(f"✅ Connected to Dependency-Track: {version_info.get('application', 'Unknown')} {version_info.get('version', 'Unknown')}")
                return True
            else:
                print(f"❌ Connection test failed with status: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False
    
    def get_projects(self):
        """Fetch all projects from DT"""
        try:
            print(f"📂 Fetching projects from: {self.base_url}/api/v1/project")
            response = requests.get(
                f"{self.base_url}/api/v1/project",
                headers=self.headers,
                timeout=30,
                verify=False
            )
            print(f"📂 Projects response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Fetched {len(data)} projects")
                return data
            else:
                print(f"❌ Error fetching projects: {response.text}")
                return []
        except Exception as e:
            print(f"❌ Error fetching projects: {e}")
            traceback.print_exc()
            return []
    
    def get_project_components(self, project_uuid):
        """Fetch components for a specific project"""
        try:
            print(f"📦 Fetching components for project: {project_uuid}")
            response = requests.get(
                f"{self.base_url}/api/v1/component/project/{project_uuid}",
                headers=self.headers,
                timeout=30,
                verify=False
            )
            
            print(f"📦 Components response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Fetched {len(data)} components for project")
                return data
            else:
                print(f"❌ Error fetching components: {response.text}")
                return []
        except Exception as e:
            print(f"❌ Error fetching components: {e}")
            traceback.print_exc()
            return []
    
    def get_component_vulnerabilities(self, component_uuid):
        """Fetch vulnerabilities for a specific component"""
        try:
            print(f"🔍 Fetching vulnerabilities for component: {component_uuid}")
            response = requests.get(
                f"{self.base_url}/api/v1/vulnerability/component/{component_uuid}",
                headers=self.headers,
                timeout=30,
                verify=False
            )
            
            print(f"🔍 Vulnerabilities response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Fetched {len(data)} vulnerabilities for component")
                return data
            else:
                print(f"❌ Error fetching vulnerabilities: {response.text}")
                return []
        except Exception as e:
            print(f"❌ Error fetching vulnerabilities: {e}")
            traceback.print_exc()
            return []
    
    def get_project_vulnerabilities(self, project_uuid):
        """Fetch all vulnerabilities for a project (more efficient)"""
        try:
            print(f"🚀 Fetching all vulnerabilities for project: {project_uuid}")
            response = requests.get(
                f"{self.base_url}/api/v1/finding/project/{project_uuid}",
                headers=self.headers,
                timeout=60,
                verify=False
            )
            
            print(f"🚀 Project vulnerabilities response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Fetched {len(data)} findings for project")
                return data
            else:
                print(f"❌ Error fetching project vulnerabilities: {response.text}")
                return []
        except Exception as e:
            print(f"❌ Error fetching project vulnerabilities: {e}")
            traceback.print_exc()
            return []

# ========================
# DATABASE OPERATIONS
# ========================

def sync_dt_projects(dt_api):
    """Sync projects from Dependency-Track"""
    try:
        projects = dt_api.get_projects()
        
        if not projects:
            print("❌ No projects found or failed to fetch projects")
            return 0
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        synced = 0
        for project in projects:
            try:
                c.execute('''INSERT OR REPLACE INTO projects 
                            (id, name, version, dt_project_id, updated_at)
                            VALUES (?, ?, ?, ?, ?)''',
                         (project['uuid'], project['name'], 
                          project.get('version', ''), project['uuid'],
                          datetime.now()))
                synced += 1
                print(f"✅ Synced project: {project['name']} v{project.get('version', 'N/A')}")
            except Exception as e:
                print(f"❌ Error syncing project {project.get('name', 'unknown')}: {e}")
        
        conn.commit()
        conn.close()
        
        log_audit('SYNC', 'PROJECT', None, 'system', {'count': synced})
        print(f"✅ Synced {synced} projects to database")
        return synced
    except Exception as e:
        print(f"❌ Error in sync_dt_projects: {e}")
        traceback.print_exc()
        return 0

def sync_dt_components(dt_api, project_id):
    """Sync components for a specific project"""
    try:
        components = dt_api.get_project_components(project_id)
        
        if not components:
            print(f"❌ No components found for project {project_id}")
            return 0
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        synced = 0
        for component in components:
            try:
                c.execute('''INSERT OR REPLACE INTO components 
                            (id, project_id, name, version, dt_component_id)
                            VALUES (?, ?, ?, ?, ?)''',
                         (component['uuid'], project_id, component['name'],
                          component.get('version', ''), component['uuid']))
                synced += 1
            except Exception as e:
                print(f"❌ Error syncing component {component.get('name', 'unknown')}: {e}")
        
        conn.commit()
        conn.close()
        
        log_audit('SYNC', 'COMPONENT', project_id, 'system', {'count': synced})
        print(f"✅ Synced {synced} components to database")
        return synced
    except Exception as e:
        print(f"❌ Error in sync_dt_components: {e}")
        traceback.print_exc()
        return 0

def sync_dt_vulnerabilities_bulk(dt_api, project_id):
    """Sync ALL vulnerabilities for a project in bulk (more efficient)"""
    try:
        print(f"🚀 Starting bulk vulnerability sync for project: {project_id}")
        
        # Get all findings for the project
        findings = dt_api.get_project_vulnerabilities(project_id)
        
        if not findings:
            print(f"❌ No vulnerabilities found for project {project_id}")
            return 0
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        synced = 0
        processed_components = set()
        
        for finding in findings:
            try:
                component = finding.get('component', {})
                vulnerability = finding.get('vulnerability', {})
                analysis = finding.get('analysis', {})
                
                component_id = component.get('uuid')
                component_name = component.get('name', 'Unknown')
                component_version = component.get('version', '')
                
                # Add component to database if not exists
                if component_id and component_id not in processed_components:
                    try:
                        c.execute('''INSERT OR IGNORE INTO components 
                                    (id, project_id, name, version, dt_component_id)
                                    VALUES (?, ?, ?, ?, ?)''',
                                 (component_id, project_id, component_name, 
                                  component_version, component_id))
                        processed_components.add(component_id)
                    except Exception as e:
                        print(f"❌ Error adding component {component_name}: {e}")
                
                # Process vulnerability
                cve_id = vulnerability.get('vulnId', 'N/A')
                if cve_id.startswith('CVE-'):
                    # Clean CVE ID
                    cve_id = cve_id.split()[0].strip()
                    
                    # Insert vulnerability
                    c.execute('''INSERT OR REPLACE INTO vulnerabilities 
                                (cve_id, component_id, project_id, description, 
                                 severity, cvss_score, attack_vector, published_date, source)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (cve_id, component_id, project_id,
                              vulnerability.get('description', '')[:1000],  # Limit description length
                              vulnerability.get('severity', 'UNKNOWN'),
                              vulnerability.get('cvssV3BaseScore', 0),
                              vulnerability.get('cvssV3AttackVector', 'UNKNOWN'),
                              vulnerability.get('published', ''),
                              'DT'))
                    
                    # If analysis exists, create assessment
                    if analysis.get('state') in ['NOT_AFFECTED', 'FALSE_POSITIVE']:
                        status = 'Not Affected'
                    elif analysis.get('state') in ['EXPLOITABLE', 'IN_TRIAGE']:
                        status = 'Affected'
                    else:
                        status = 'Under Review'
                    
                    if analysis.get('state') != 'NOT_SET':
                        c.execute('''INSERT OR REPLACE INTO assessments 
                                    (vulnerability_id, cve_id, status, assessment_text, 
                                     assessed_by, assessed_at, updated_at)
                                    SELECT v.id, ?, ?, ?, ?, ?, ?
                                    FROM vulnerabilities v 
                                    WHERE v.cve_id = ? AND v.project_id = ?''',
                                 (cve_id, status, 
                                  f"Imported from DT analysis: {analysis.get('state', 'UNKNOWN')}",
                                  'system', datetime.now(), datetime.now(),
                                  cve_id, project_id))
                    
                    synced += 1
                    
                    if synced % 100 == 0:
                        print(f"📊 Processed {synced} vulnerabilities...")
                        
            except Exception as e:
                print(f"❌ Error processing finding: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        log_audit('SYNC', 'VULNERABILITY', project_id, 'system', {'count': synced})
        print(f"✅ Synced {synced} vulnerabilities to database for project {project_id}")
        return synced
        
    except Exception as e:
        print(f"❌ Error in sync_dt_vulnerabilities_bulk: {e}")
        traceback.print_exc()
        return 0

def import_assessment_from_excel(file):
    """Import assessments from Excel file with better handling"""
    try:
        print("📥 Starting Excel import...")
        df = pd.read_excel(file)
        
        # Normalize column names
        df.columns = [col.strip().lower().replace(' ', '_') for col in df.columns]
        print(f"📊 Excel columns: {list(df.columns)}")
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        imported = 0
        updated = 0
        errors = 0
        
        for index, row in df.iterrows():
            try:
                # Try different possible column names for CVE ID
                cve_id = None
                for col in ['cve_id', 'cve', 'vulnerability_no', 'vulnerability_id']:
                    if col in df.columns:
                        cve_val = str(row[col]).strip()
                        if cve_val.startswith('CVE-'):
                            cve_id = cve_val.split()[0]  # Take only first part if there are aliases
                            break
                
                if not cve_id:
                    print(f"⚠️ Row {index}: No valid CVE ID found")
                    errors += 1
                    continue
                
                # Get status from various possible columns
                status = 'Under Review'
                assessment_text = ''
                
                # Status detection
                for status_col in ['status', 'impacted_/_not_impact', 'assessment_status']:
                    if status_col in df.columns:
                        status_val = str(row[status_col]).strip().lower()
                        if 'not affected' in status_val or 'not impact' in status_val:
                            status = 'Not Affected'
                        elif 'affected' in status_val:
                            status = 'Affected'
                        break
                
                # Assessment text
                for text_col in ['assessment', 'assessment_text', 'comments', 'notes']:
                    if text_col in df.columns and pd.notna(row[text_col]):
                        assessment_text = str(row[text_col])
                        break
                
                print(f"📝 Processing {cve_id}: status={status}")
                
                # Find vulnerability ID
                c.execute('SELECT id FROM vulnerabilities WHERE cve_id = ?', (cve_id,))
                result = c.fetchone()
                
                vuln_id = result[0] if result else None
                
                if vuln_id:
                    # Update existing assessment
                    c.execute('''UPDATE assessments 
                                SET status = ?, assessment_text = ?, assessed_by = ?, updated_at = ?
                                WHERE cve_id = ?''',
                             (status, assessment_text, 'imported', datetime.now(), cve_id))
                    
                    if c.rowcount == 0:
                        # Insert new assessment
                        c.execute('''INSERT INTO assessments 
                                    (vulnerability_id, cve_id, status, assessment_text, assessed_by)
                                    VALUES (?, ?, ?, ?, ?)''',
                                 (vuln_id, cve_id, status, assessment_text, 'imported'))
                    
                    updated += 1
                else:
                    # Create assessment without vulnerability link
                    c.execute('''INSERT INTO assessments 
                                (cve_id, status, assessment_text, assessed_by)
                                VALUES (?, ?, ?, ?)''',
                             (cve_id, status, assessment_text, 'imported'))
                    imported += 1
                
            except Exception as e:
                print(f"❌ Error importing row {index}: {e}")
                errors += 1
                continue
        
        conn.commit()
        conn.close()
        
        log_audit('IMPORT', 'ASSESSMENT', None, 'user', {
            'imported': imported,
            'updated': updated,
            'errors': errors
        })
        
        print(f"✅ Import completed: {imported} new, {updated} updated, {errors} errors")
        return {'imported': imported, 'updated': updated, 'errors': errors}
        
    except Exception as e:
        print(f"❌ Error importing assessments: {e}")
        traceback.print_exc()
        return {'imported': 0, 'updated': 0, 'errors': 1}

def export_assessment_template():
    """Export assessment template Excel file"""
    try:
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        
        # Get all vulnerabilities with current assessments
        query = '''
            SELECT 
                v.cve_id,
                COALESCE(a.status, 'Under Review') as current_status,
                COALESCE(a.assessment_text, '') as current_assessment,
                v.severity,
                v.component_id,
                c.name as component_name
            FROM vulnerabilities v
            LEFT JOIN components c ON v.component_id = c.id
            LEFT JOIN assessments a ON v.cve_id = a.cve_id
            ORDER BY v.severity DESC, v.cve_id
        '''
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        # Create template with instructions
        template_data = {
            'CVE_ID': df['cve_id'],
            'CURRENT_STATUS': df['current_status'],
            'NEW_STATUS': [''] * len(df),
            'ASSESSMENT_NOTES': [''] * len(df),
            'SEVERITY': df['severity'],
            'COMPONENT': df['component_name']
        }
        
        template_df = pd.DataFrame(template_data)
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            template_df.to_excel(writer, sheet_name='Assessment_Template', index=False)
            
            # Add instructions sheet
            instructions = pd.DataFrame({
                'Column': ['CVE_ID', 'CURRENT_STATUS', 'NEW_STATUS', 'ASSESSMENT_NOTES', 'SEVERITY', 'COMPONENT'],
                'Description': [
                    'CVE ID (do not modify)',
                    'Current assessment status (do not modify)',
                    'New status: Affected, Not Affected, or Under Review',
                    'Assessment notes and rationale',
                    'Vulnerability severity (do not modify)',
                    'Affected component (do not modify)'
                ],
                'Valid_Values': [
                    'CVE-YYYY-NNNN*',
                    'Affected, Not Affected, Under Review',
                    'Affected, Not Affected, Under Review',
                    'Free text',
                    'CRITICAL, HIGH, MEDIUM, LOW',
                    'Component name'
                ]
            })
            instructions.to_excel(writer, sheet_name='Instructions', index=False)
        
        output.seek(0)
        return output
        
    except Exception as e:
        print(f"❌ Error exporting template: {e}")
        traceback.print_exc()
        return None

def get_dashboard_metrics(filters=None):
    """Get dashboard metrics with optional filters"""
    try:
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        where_clauses = []
        params = []
        
        if filters:
            if filters.get('project_id'):
                where_clauses.append('v.project_id = ?')
                params.append(filters['project_id'])
            if filters.get('severity'):
                where_clauses.append('v.severity = ?')
                params.append(filters['severity'])
            if filters.get('status'):
                if filters['status'] == 'Under Review':
                    where_clauses.append('(a.status IS NULL OR a.status = ?)')
                else:
                    where_clauses.append('a.status = ?')
                params.append(filters['status'])
        
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        # Total vulnerabilities by severity
        c.execute(f'''
            SELECT v.severity, COUNT(*) as count
            FROM vulnerabilities v
            LEFT JOIN assessments a ON v.id = a.vulnerability_id
            {where_sql}
            GROUP BY v.severity
        ''', params)
        severity_counts = dict(c.fetchall())
        
        # Status breakdown
        c.execute(f'''
            SELECT 
                COALESCE(a.status, 'Under Review') as status, 
                COUNT(*) as count
            FROM vulnerabilities v
            LEFT JOIN assessments a ON v.id = a.vulnerability_id
            {where_sql}
            GROUP BY status
        ''', params)
        status_counts = dict(c.fetchall())
        
        # Recent vulnerabilities
        c.execute(f'''
            SELECT v.cve_id, v.severity, v.published_date, c.name as component_name,
                   COALESCE(a.status, 'Under Review') as status
            FROM vulnerabilities v
            LEFT JOIN components c ON v.component_id = c.id
            LEFT JOIN assessments a ON v.id = a.vulnerability_id
            {where_sql}
            ORDER BY v.published_date DESC
            LIMIT 10
        ''', params)
        recent_vulns = c.fetchall()
        
        conn.close()
        
        return {
            'severity': severity_counts,
            'status': status_counts,
            'recent_vulns': recent_vulns,
            'total_vulnerabilities': sum(severity_counts.values())
        }
    except Exception as e:
        print(f"❌ Error getting dashboard metrics: {e}")
        traceback.print_exc()
        return {'severity': {}, 'status': {}, 'recent_vulns': [], 'total_vulnerabilities': 0}

# ========================
# API ROUTES
# ========================

@app.route('/')
def index():
    """Serve main dashboard page"""
    try:
        return render_template('dashboard.html')
    except Exception as e:
        return f"""
        <html>
            <body>
                <h1>Error loading dashboard</h1>
                <p>Make sure dashboard.html is in the 'templates' folder</p>
                <p>Error: {e}</p>
            </body>
        </html>
        """, 500

@app.route('/api/config', methods=['POST'])
def save_config():
    """Save DT configuration"""
    try:
        data = request.json
        with open('dt_config.json', 'w') as f:
            json.dump(data, f)
        return jsonify({'success': True, 'message': 'Configuration saved'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get DT configuration"""
    try:
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        return jsonify(config)
    except FileNotFoundError:
        return jsonify({'url': '', 'api_key': ''})

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test DT connection"""
    try:
        data = request.json
        dt_api = DependencyTrackAPI(data['url'], data['api_key'])
        
        if dt_api.test_connection():
            return jsonify({'success': True, 'message': '✅ Connection successful!'})
        else:
            return jsonify({'success': False, 'error': '❌ Cannot connect to Dependency-Track'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Connection test failed: {str(e)}'})

@app.route('/api/sync/projects', methods=['POST'])
def sync_projects():
    """Sync projects from DT"""
    try:
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        
        dt_api = DependencyTrackAPI(config['url'], config['api_key'])
        
        if not dt_api.test_connection():
            return jsonify({'success': False, 'error': 'Cannot connect to Dependency-Track'})
        
        count = sync_dt_projects(dt_api)
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/projects', methods=['GET'])
def get_projects():
    """Get all projects from database"""
    try:
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT id, name, version FROM projects ORDER BY name')
        projects = [{'id': row[0], 'name': row[1], 'version': row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify(projects)
    except Exception as e:
        return jsonify([])

@app.route('/api/sync/vulnerabilities/<project_id>', methods=['POST'])
def sync_vulnerabilities(project_id):
    """Sync ALL vulnerabilities for a project"""
    try:
        print(f"🚀 Starting vulnerability sync for project: {project_id}")
        
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        
        dt_api = DependencyTrackAPI(config['url'], config['api_key'])
        count = sync_dt_vulnerabilities_bulk(dt_api, project_id)
        
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get vulnerabilities with filters and pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        project_id = request.args.get('project_id')
        severity = request.args.get('severity')
        status = request.args.get('status')
        search = request.args.get('search', '')
        
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        query = '''
            SELECT 
                v.id, v.cve_id, v.description, v.severity, v.cvss_score,
                v.attack_vector, v.published_date, c.name as component_name,
                p.name as project_name,
                COALESCE(a.status, 'Under Review') as status,
                a.assessment_text, a.id as assessment_id,
                v.created_at
            FROM vulnerabilities v
            LEFT JOIN components c ON v.component_id = c.id
            LEFT JOIN projects p ON v.project_id = p.id
            LEFT JOIN assessments a ON v.cve_id = a.cve_id
            WHERE 1=1
        '''
        params = []
        
        if project_id:
            query += ' AND v.project_id = ?'
            params.append(project_id)
        if severity:
            query += ' AND v.severity = ?'
            params.append(severity)
        if status:
            if status == 'Under Review':
                query += ' AND (a.status IS NULL OR a.status = ?)'
            else:
                query += ' AND a.status = ?'
            params.append(status)
        if search:
            query += ' AND (v.cve_id LIKE ? OR v.description LIKE ? OR c.name LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        
        # Count total
        count_query = f'SELECT COUNT(*) FROM ({query})'
        c.execute(count_query, params)
        total = c.fetchone()[0]
        
        # Get data with pagination
        query += ' ORDER BY v.cvss_score DESC, v.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        c.execute(query, params)
        
        vulnerabilities = []
        for row in c.fetchall():
            vulnerabilities.append({
                'id': row[0],
                'cve_id': row[1],
                'description': (row[2] or '')[:200] + '...' if row[2] and len(row[2]) > 200 else row[2],
                'severity': row[3],
                'cvss_score': row[4],
                'attack_vector': row[5],
                'published_date': row[6],
                'component_name': row[7],
                'project_name': row[8],
                'status': row[9],
                'assessment_text': row[10],
                'assessment_id': row[11],
                'created_at': row[12]
            })
        
        conn.close()
        
        return jsonify({
            'vulnerabilities': vulnerabilities,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        return jsonify({'vulnerabilities': [], 'pagination': {'page': 1, 'per_page': 50, 'total': 0, 'pages': 0}})

@app.route('/api/assessment', methods=['POST'])
def save_assessment():
    """Save or update assessment"""
    try:
        data = request.json
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        # Check if assessment exists
        c.execute('SELECT id FROM assessments WHERE cve_id = ?', (data['cve_id'],))
        existing = c.fetchone()
        
        if existing:
            # Update existing
            c.execute('''UPDATE assessments 
                        SET status = ?, assessment_text = ?, assessed_by = ?, updated_at = ?
                        WHERE cve_id = ?''',
                     (data['status'], data.get('assessment_text', ''), 
                      data.get('assessed_by', 'user'), datetime.now(), data['cve_id']))
        else:
            # Insert new
            c.execute('''INSERT INTO assessments 
                        (vulnerability_id, cve_id, status, assessment_text, assessed_by)
                        VALUES (?, ?, ?, ?, ?)''',
                     (data.get('vulnerability_id'), data['cve_id'], 
                      data['status'], data.get('assessment_text', ''),
                      data.get('assessed_by', 'user')))
        
        conn.commit()
        conn.close()
        
        log_audit('UPDATE', 'ASSESSMENT', data['cve_id'], 'user', data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/assessment/bulk', methods=['POST'])
def save_bulk_assessments():
    """Save multiple assessments at once"""
    try:
        data = request.json
        assessments = data.get('assessments', [])
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        c = conn.cursor()
        
        updated = 0
        for assessment in assessments:
            try:
                c.execute('''INSERT OR REPLACE INTO assessments 
                            (vulnerability_id, cve_id, status, assessment_text, assessed_by, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                         (assessment.get('vulnerability_id'), assessment['cve_id'],
                          assessment['status'], assessment.get('assessment_text', ''),
                          'user', datetime.now()))
                updated += 1
            except Exception as e:
                print(f"Error updating assessment for {assessment.get('cve_id')}: {e}")
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'updated': updated})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/assessment/import', methods=['POST'])
def import_assessment():
    """Import assessments from Excel"""
    try:
        file = request.files['file']
        result = import_assessment_from_excel(file)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/assessment/template', methods=['GET'])
def download_template():
    """Download assessment template"""
    try:
        output = export_assessment_template()
        if output:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'assessment_template_{timestamp}.xlsx'
            )
        else:
            return "Error generating template", 500
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/api/dashboard/metrics', methods=['GET'])
def dashboard_metrics():
    """Get dashboard metrics"""
    try:
        filters = {
            'project_id': request.args.get('project_id'),
            'severity': request.args.get('severity'),
            'status': request.args.get('status')
        }
        filters = {k: v for k, v in filters.items() if v}
        
        metrics = get_dashboard_metrics(filters)
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'severity': {}, 'status': {}, 'recent_vulns': [], 'total_vulnerabilities': 0})

@app.route('/api/export', methods=['GET'])
def export_report():
    """Export vulnerability report to Excel"""
    try:
        project_id = request.args.get('project_id')
        
        conn = sqlite3.connect('vulnerability_tracker.db', check_same_thread=False)
        
        query = '''
            SELECT 
                v.cve_id, v.severity, v.cvss_score, v.description,
                c.name as component, c.version as component_version,
                p.name as project_name,
                COALESCE(a.status, 'Under Review') as status,
                a.assessment_text, v.published_date, v.attack_vector
            FROM vulnerabilities v
            LEFT JOIN components c ON v.component_id = c.id
            LEFT JOIN projects p ON v.project_id = p.id
            LEFT JOIN assessments a ON v.cve_id = a.cve_id
        '''
        
        if project_id:
            query += ' WHERE v.project_id = ?'
            df = pd.read_sql_query(query, conn, params=(project_id,))
        else:
            df = pd.read_sql_query(query, conn)
        
        conn.close()
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Vulnerability_Report')
        
        output.seek(0)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'vulnerability_report_{timestamp}.xlsx'
        )
    except Exception as e:
        return f"Error exporting report: {str(e)}", 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Custom Dependency-Track Dashboard - COMPLETE VERSION")
    print("=" * 60)
    
    # Initialize database
    if init_db():
        print("✅ Database ready: vulnerability_tracker.db")
    else:
        print("❌ Database initialization failed!")
    
    print("=" * 60)
    print("Starting Flask server...")
    print("Open your browser: http://localhost:5001")
    print("=" * 60)
    
    app.run(debug=True, port=5001, host='0.0.0.0', threaded=True)