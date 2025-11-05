"""
Custom Dependency-Track Dashboard
Complete solution with SQLite storage, DT API integration, and assessment management
"""

from flask import Flask, render_template, request, jsonify, send_file
import requests
import sqlite3
import pandas as pd
from datetime import datetime
import json
import io
from openpyxl.styles import Alignment, PatternFill, Font
from openpyxl import load_workbook

app = Flask(__name__)

# ========================
# DATABASE SETUP
# ========================

def init_db():
    """Initialize SQLite database with tables"""
    conn = sqlite3.connect('vulnerability_tracker.db')
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
        FOREIGN KEY (project_id) REFERENCES projects(id),
        UNIQUE(cve_id, component_id)
    )''')
    
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

def log_audit(action, entity_type, entity_id, user, details):
    """Log actions for compliance"""
    conn = sqlite3.connect('vulnerability_tracker.db')
    c = conn.cursor()
    c.execute('''INSERT INTO audit_log (action, entity_type, entity_id, user, details)
                 VALUES (?, ?, ?, ?, ?)''',
              (action, entity_type, entity_id, user, json.dumps(details)))
    conn.commit()
    conn.close()

# ========================
# DEPENDENCY-TRACK API
# ========================

class DependencyTrackAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-Api-Key': api_key,
            'Content-Type': 'application/json'
        }
    
    def get_projects(self):
        """Fetch all projects from DT"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/project",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            print(f"Error fetching projects: {e}")
            return []
    
    def get_project_components(self, project_uuid):
        """Fetch components for a specific project"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/component/project/{project_uuid}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            print(f"Error fetching components: {e}")
            return []
    
    def get_component_vulnerabilities(self, component_uuid):
        """Fetch vulnerabilities for a specific component"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/vulnerability/component/{component_uuid}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            print(f"Error fetching vulnerabilities: {e}")
            return []

# ========================
# DATABASE OPERATIONS
# ========================

def sync_dt_projects(dt_api):
    """Sync projects from Dependency-Track"""
    projects = dt_api.get_projects()
    conn = sqlite3.connect('vulnerability_tracker.db')
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
        except Exception as e:
            print(f"Error syncing project {project['name']}: {e}")
    
    conn.commit()
    conn.close()
    
    log_audit('SYNC', 'PROJECT', None, 'system', {'count': synced})
    return synced

def sync_dt_components(dt_api, project_id):
    """Sync components for a specific project"""
    components = dt_api.get_project_components(project_id)
    conn = sqlite3.connect('vulnerability_tracker.db')
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
            print(f"Error syncing component: {e}")
    
    conn.commit()
    conn.close()
    
    log_audit('SYNC', 'COMPONENT', project_id, 'system', {'count': synced})
    return synced

def sync_dt_vulnerabilities(dt_api, component_id, project_id):
    """Sync vulnerabilities for a specific component"""
    vulns = dt_api.get_component_vulnerabilities(component_id)
    conn = sqlite3.connect('vulnerability_tracker.db')
    c = conn.cursor()
    
    synced = 0
    for vuln in vulns:
        try:
            vulnerability = vuln.get('vulnerability', {})
            cve_id = vulnerability.get('vulnId', 'N/A')
            
            # Remove aliases from CVE ID (keep only CVE-YYYY-XXXXX format)
            if cve_id.startswith('CVE-'):
                cve_id = cve_id.split()[0]  # Take first part only
            
            c.execute('''INSERT OR IGNORE INTO vulnerabilities 
                        (cve_id, component_id, project_id, description, 
                         severity, cvss_score, attack_vector, published_date, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (cve_id, component_id, project_id,
                      vulnerability.get('description', ''),
                      vulnerability.get('severity', 'UNKNOWN'),
                      vulnerability.get('cvssV3BaseScore', 0),
                      vulnerability.get('cvssV3AttackVector', 'UNKNOWN'),
                      vulnerability.get('published', ''),
                      'DT'))
            synced += 1
        except Exception as e:
            print(f"Error syncing vulnerability: {e}")
    
    conn.commit()
    conn.close()
    
    log_audit('SYNC', 'VULNERABILITY', component_id, 'system', {'count': synced})
    return synced

def import_assessment_from_excel(file):
    """Import assessments from Excel file"""
    try:
        df = pd.read_excel(file)
        conn = sqlite3.connect('vulnerability_tracker.db')
        c = conn.cursor()
        
        imported = 0
        for _, row in df.iterrows():
            cve_id = str(row.get('Vulnerability No', '')).strip()
            status = 'Not Affected' if 'Not Impact' in str(row.get('Impacted / Not Impact', '')) else 'Under Review'
            assessment = str(row.get('Assessment', ''))
            
            if cve_id.startswith('CVE-'):
                # Find vulnerability in database
                c.execute('SELECT id FROM vulnerabilities WHERE cve_id = ?', (cve_id,))
                result = c.fetchone()
                
                vuln_id = result[0] if result else None
                
                # Insert or update assessment
                c.execute('''INSERT OR REPLACE INTO assessments 
                            (vulnerability_id, cve_id, status, assessment_text, 
                             assessed_by, assessed_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (vuln_id, cve_id, status, assessment,
                          'imported', datetime.now(), datetime.now()))
                imported += 1
        
        conn.commit()
        conn.close()
        
        log_audit('IMPORT', 'ASSESSMENT', None, 'user', {'count': imported})
        return imported
    except Exception as e:
        print(f"Error importing assessments: {e}")
        return 0

def get_dashboard_metrics(filters=None):
    """Get dashboard metrics with optional filters"""
    conn = sqlite3.connect('vulnerability_tracker.db')
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
            where_clauses.append('a.status = ?')
            params.append(filters['status'])
        if filters.get('date_from'):
            where_clauses.append('v.created_at >= ?')
            params.append(filters['date_from'])
        if filters.get('date_to'):
            where_clauses.append('v.created_at <= ?')
            params.append(filters['date_to'])
    
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
    
    # Component breakdown
    c.execute(f'''
        SELECT c.name, COUNT(v.id) as count
        FROM vulnerabilities v
        JOIN components c ON v.component_id = c.id
        LEFT JOIN assessments a ON v.id = a.vulnerability_id
        {where_sql}
        GROUP BY c.name
        ORDER BY count DESC
        LIMIT 10
    ''', params)
    component_counts = c.fetchall()
    
    # Trends (last 6 months)
    c.execute(f'''
        SELECT 
            strftime('%Y-%m', v.created_at) as month,
            COUNT(*) as count
        FROM vulnerabilities v
        LEFT JOIN assessments a ON v.id = a.vulnerability_id
        {where_sql}
        GROUP BY month
        ORDER BY month DESC
        LIMIT 6
    ''', params)
    trends = c.fetchall()
    
    conn.close()
    
    return {
        'severity': severity_counts,
        'status': status_counts,
        'components': component_counts,
        'trends': trends
    }

# ========================
# API ROUTES
# ========================

@app.route('/')
def index():
    """Serve main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/config', methods=['POST'])
def save_config():
    """Save DT configuration"""
    data = request.json
    with open('dt_config.json', 'w') as f:
        json.dump(data, f)
    return jsonify({'success': True})

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get DT configuration"""
    try:
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        return jsonify(config)
    except:
        return jsonify({'url': '', 'api_key': ''})

@app.route('/api/sync/projects', methods=['POST'])
def sync_projects():
    """Sync projects from DT"""
    try:
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        
        dt_api = DependencyTrackAPI(config['url'], config['api_key'])
        count = sync_dt_projects(dt_api)
        
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/projects', methods=['GET'])
def get_projects():
    """Get all projects from database"""
    conn = sqlite3.connect('vulnerability_tracker.db')
    c = conn.cursor()
    c.execute('SELECT id, name, version FROM projects ORDER BY name')
    projects = [{'id': row[0], 'name': row[1], 'version': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(projects)

@app.route('/api/sync/components/<project_id>', methods=['POST'])
def sync_components(project_id):
    """Sync components for a project"""
    try:
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        
        dt_api = DependencyTrackAPI(config['url'], config['api_key'])
        count = sync_dt_components(dt_api, project_id)
        
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/components/<project_id>', methods=['GET'])
def get_components(project_id):
    """Get components for a project"""
    conn = sqlite3.connect('vulnerability_tracker.db')
    c = conn.cursor()
    c.execute('SELECT id, name, version FROM components WHERE project_id = ? ORDER BY name', (project_id,))
    components = [{'id': row[0], 'name': row[1], 'version': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(components)

@app.route('/api/sync/vulnerabilities/<component_id>', methods=['POST'])
def sync_vulnerabilities(component_id):
    """Sync vulnerabilities for a component"""
    try:
        data = request.json
        project_id = data.get('project_id')
        
        with open('dt_config.json', 'r') as f:
            config = json.load(f)
        
        dt_api = DependencyTrackAPI(config['url'], config['api_key'])
        count = sync_dt_vulnerabilities(dt_api, component_id, project_id)
        
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get vulnerabilities with filters"""
    project_id = request.args.get('project_id')
    component_id = request.args.get('component_id')
    severity = request.args.get('severity')
    status = request.args.get('status')
    
    conn = sqlite3.connect('vulnerability_tracker.db')
    c = conn.cursor()
    
    query = '''
        SELECT 
            v.id, v.cve_id, v.description, v.severity, v.cvss_score,
            v.attack_vector, v.published_date, c.name as component_name,
            COALESCE(a.status, 'Under Review') as status,
            a.assessment_text, v.created_at
        FROM vulnerabilities v
        LEFT JOIN components c ON v.component_id = c.id
        LEFT JOIN assessments a ON v.id = a.vulnerability_id
        WHERE 1=1
    '''
    params = []
    
    if project_id:
        query += ' AND v.project_id = ?'
        params.append(project_id)
    if component_id:
        query += ' AND v.component_id = ?'
        params.append(component_id)
    if severity:
        query += ' AND v.severity = ?'
        params.append(severity)
    if status:
        query += ' AND COALESCE(a.status, "Under Review") = ?'
        params.append(status)
    
    query += ' ORDER BY v.cvss_score DESC, v.created_at DESC'
    
    c.execute(query, params)
    
    vulnerabilities = []
    for row in c.fetchall():
        vulnerabilities.append({
            'id': row[0],
            'cve_id': row[1],
            'description': row[2],
            'severity': row[3],
            'cvss_score': row[4],
            'attack_vector': row[5],
            'published_date': row[6],
            'component_name': row[7],
            'status': row[8],
            'assessment_text': row[9],
            'created_at': row[10]
        })
    
    conn.close()
    return jsonify(vulnerabilities)

@app.route('/api/assessment', methods=['POST'])
def save_assessment():
    """Save or update assessment"""
    try:
        data = request.json
        conn = sqlite3.connect('vulnerability_tracker.db')
        c = conn.cursor()
        
        c.execute('''INSERT OR REPLACE INTO assessments 
                    (vulnerability_id, cve_id, status, assessment_text, 
                     assessed_by, assessed_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (data.get('vulnerability_id'), data['cve_id'], 
                  data['status'], data['assessment_text'],
                  data.get('assessed_by', 'user'), 
                  datetime.now(), datetime.now()))
        
        conn.commit()
        conn.close()
        
        log_audit('UPDATE', 'ASSESSMENT', data['cve_id'], 'user', data)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/assessment/import', methods=['POST'])
def import_assessment():
    """Import assessments from Excel"""
    try:
        file = request.files['file']
        count = import_assessment_from_excel(file)
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/dashboard/metrics', methods=['GET'])
def dashboard_metrics():
    """Get dashboard metrics"""
    filters = {
        'project_id': request.args.get('project_id'),
        'severity': request.args.get('severity'),
        'status': request.args.get('status'),
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to')
    }
    # Remove None values
    filters = {k: v for k, v in filters.items() if v}
    
    metrics = get_dashboard_metrics(filters)
    return jsonify(metrics)

@app.route('/api/export', methods=['GET'])
def export_report():
    """Export vulnerability report to Excel"""
    project_id = request.args.get('project_id')
    
    conn = sqlite3.connect('vulnerability_tracker.db')
    query = '''
        SELECT 
            v.cve_id, v.severity, v.cvss_score, c.name as component,
            COALESCE(a.status, 'Under Review') as status,
            a.assessment_text, v.description
        FROM vulnerabilities v
        LEFT JOIN components c ON v.component_id = c.id
        LEFT JOIN assessments a ON v.id = a.vulnerability_id
    '''
    
    if project_id:
        query += ' WHERE v.project_id = ?'
        df = pd.read_sql_query(query, conn, params=(project_id,))
    else:
        df = pd.read_sql_query(query, conn)
    
    conn.close()
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Vulnerabilities')
    
    output.seek(0)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'vulnerability_report_{timestamp}.xlsx'
    )

if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("Custom Dependency-Track Dashboard")
    print("=" * 60)
    print("Database initialized: vulnerability_tracker.db")
    print("Starting server...")
    print("Open your browser: http://localhost:5001")
    print("=" * 60)
    
    # Note: templates/dashboard.html needs to be created separately
    app.run(debug=True, port=5001)