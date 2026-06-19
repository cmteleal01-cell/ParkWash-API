import sqlite3
import uuid
import hashlib
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# Configuração
DATABASE_FILE = "parkwash.db"

# ============================================================================
# INICIALIZAÇÃO DO BANCO DE DADOS
# ============================================================================

def init_database():
    """Cria as tabelas se não existirem"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cur = conn.cursor()
        
        # Tabela de máquinas licenciadas
        cur.execute("""
            CREATE TABLE IF NOT EXISTS machines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                license_key TEXT UNIQUE NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_name TEXT,
                notes TEXT
            )
        """)
        
        # Tabela de versões
        cur.execute("""
            CREATE TABLE IF NOT EXISTS versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_number TEXT UNIQUE NOT NULL,
                download_url TEXT NOT NULL,
                changelog TEXT,
                released_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        """)
        
        # Tabela de logs de validação
        cur.execute("""
            CREATE TABLE IF NOT EXISTS validation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT,
                license_key TEXT,
                ip_address TEXT,
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        return False

# ============================================================================
# HANDLER HTTP
# ============================================================================

class APIHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/":
            self.send_json({"status": "ParkWash API Online", "version": "1.0"})
        
        elif path == "/health":
            self.send_json({"status": "online", "version": "1.0", "database": "connected"})
        
        elif path == "/version/latest":
            self.get_latest_version()
        
        else:
            self.send_json({"error": "Not found"}, 404)
    
    def do_POST(self):
        """Handle POST requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}
        
        if path == "/setup":
            self.setup_database()
        
        elif path == "/license/validate":
            self.validate_license(data)
        
        elif path == "/admin/generate-license":
            self.generate_license(data)
        
        elif path == "/admin/add-version":
            self.add_version(data)
        
        else:
            self.send_json({"error": "Not found"}, 404)
    
    # ========================================================================
    # ENDPOINTS
    # ========================================================================
    
    def setup_database(self):
        """Setup inicial - cria tabelas"""
        if init_database():
            self.send_json({
                "status": "success",
                "message": "Database initialized successfully",
                "tables": ["machines", "versions", "validation_logs"]
            })
        else:
            self.send_json({"error": "Failed to initialize database"}, 500)
    
    def validate_license(self, data):
        """Valida licença de máquina"""
        try:
            mac_address = data.get("mac_address")
            license_key = data.get("license_key")
            
            if not mac_address or not license_key:
                self.send_json({"error": "Missing mac_address or license_key"}, 400)
                return
            
            conn = sqlite3.connect(DATABASE_FILE)
            cur = conn.cursor()
            
            # Procura máquina
            cur.execute(
                "SELECT id, active FROM machines WHERE mac_address = ? AND license_key = ?",
                (mac_address, license_key)
            )
            machine = cur.fetchone()
            
            # Log da tentativa
            cur.execute(
                "INSERT INTO validation_logs (mac_address, license_key, status) VALUES (?, ?, ?)",
                (mac_address, license_key, "valid" if machine else "invalid")
            )
            
            if machine:
                machine_id, is_active = machine
                
                if not is_active:
                    conn.commit()
                    cur.close()
                    conn.close()
                    self.send_json({"valid": False, "message": "License is inactive"})
                    return
                
                # Atualiza last_check
                cur.execute(
                    "UPDATE machines SET last_check = CURRENT_TIMESTAMP WHERE id = ?",
                    (machine_id,)
                )
                
                # Busca versão mais recente
                cur.execute(
                    "SELECT version_number, download_url, changelog FROM versions WHERE is_active = 1 ORDER BY released_at DESC LIMIT 1"
                )
                version = cur.fetchone()
                
                conn.commit()
                cur.close()
                conn.close()
                
                if version:
                    self.send_json({
                        "valid": True,
                        "message": "License is valid",
                        "version": version[0],
                        "download_url": version[1]
                    })
                else:
                    self.send_json({
                        "valid": True,
                        "message": "License is valid (no new version)"
                    })
            else:
                conn.commit()
                cur.close()
                conn.close()
                self.send_json({
                    "valid": False,
                    "message": "Invalid MAC address or license key"
                })
        
        except Exception as e:
            self.send_json({"error": f"Validation error: {str(e)}"}, 500)
    
    def get_latest_version(self):
        """Retorna versão mais recente disponível"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cur = conn.cursor()
            
            cur.execute(
                "SELECT version_number, download_url, changelog FROM versions WHERE is_active = 1 ORDER BY released_at DESC LIMIT 1"
            )
            version = cur.fetchone()
            
            cur.close()
            conn.close()
            
            if version:
                self.send_json({
                    "version_number": version[0],
                    "download_url": version[1],
                    "changelog": version[2] or ""
                })
            else:
                self.send_json({"error": "No version found"}, 404)
        
        except Exception as e:
            self.send_json({"error": f"Error: {str(e)}"}, 500)
    
    def generate_license(self, data):
        """ADMIN ONLY: Gera nova licença para máquina"""
        try:
            mac_address = data.get("mac_address")
            client_name = data.get("client_name", "")
            
            if not mac_address:
                self.send_json({"error": "Missing mac_address"}, 400)
                return
            
            # Gera license_key única
            license_key = hashlib.sha256(f"{mac_address}{uuid.uuid4()}".encode()).hexdigest()[:64]
            
            conn = sqlite3.connect(DATABASE_FILE)
            cur = conn.cursor()
            
            cur.execute(
                "INSERT INTO machines (mac_address, license_key, client_name) VALUES (?, ?, ?)",
                (mac_address, license_key, client_name)
            )
            
            conn.commit()
            cur.close()
            conn.close()
            
            self.send_json({
                "status": "success",
                "mac_address": mac_address,
                "license_key": license_key,
                "message": "License generated successfully"
            })
        
        except Exception as e:
            self.send_json({"error": f"Error: {str(e)}"}, 500)
    
    def add_version(self, data):
        """ADMIN ONLY: Adiciona nova versão"""
        try:
            version_number = data.get("version_number")
            download_url = data.get("download_url")
            changelog = data.get("changelog", "")
            
            if not version_number or not download_url:
                self.send_json({"error": "Missing version_number or download_url"}, 400)
                return
            
            conn = sqlite3.connect(DATABASE_FILE)
            cur = conn.cursor()
            
            cur.execute(
                "INSERT INTO versions (version_number, download_url, changelog) VALUES (?, ?, ?)",
                (version_number, download_url, changelog)
            )
            
            conn.commit()
            cur.close()
            conn.close()
            
            self.send_json({
                "status": "success",
                "version": version_number,
                "message": "Version added successfully"
            })
        
        except Exception as e:
            self.send_json({"error": f"Error: {str(e)}"}, 500)
    
    # ========================================================================
    # UTILITIES
    # ========================================================================
    
    def send_json(self, data, status_code=200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    init_database()
    
    server = HTTPServer(("0.0.0.0", 8000), APIHandler)
    print("🚀 ParkWash API running on http://0.0.0.0:8000")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
        server.server_close()