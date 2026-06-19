import sqlite3
import uuid
import hashlib
import json
import hmac
import base64
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os

# Configuração
DATABASE_FILE = "parkwash.db"
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "change_me_in_production_default_key_123")

# ============================================================================
# AUTENTICAÇÃO JWT SIMPLES
# ============================================================================

def generate_admin_token(expires_in=86400):
    """
    Gera token JWT para admin (válido por 24h por padrão)
    Retorna: token string
    """
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
        "role": "admin"
    }
    
    # Header
    header = {"alg": "HS256", "typ": "JWT"}
    
    # Encoding
    def base64_url_encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    
    header_encoded = base64_url_encode(header)
    payload_encoded = base64_url_encode(payload)
    
    # Signature
    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        ADMIN_SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    token = f"{message}.{signature_encoded}"
    return token

def verify_admin_token(token):
    """
    Verifica se token JWT é válido
    Retorna: (True, None) se válido, (False, erro_msg) se inválido
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid token format"
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Reconstrói a mensagem e verifica assinatura
        message = f"{header_encoded}.{payload_encoded}"
        
        # Padding
        payload_padded = payload_encoded + '=' * (4 - len(payload_encoded) % 4)
        
        # Decodifica payload
        try:
            payload_decoded = base64.urlsafe_b64decode(payload_padded).decode()
            payload = json.loads(payload_decoded)
        except:
            return False, "Invalid token payload"
        
        # Verifica assinatura
        expected_signature = hmac.new(
            ADMIN_SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        expected_signature_encoded = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')
        
        if signature_encoded != expected_signature_encoded:
            return False, "Invalid signature"
        
        # Verifica expiração
        if int(time.time()) > payload.get("exp", 0):
            return False, "Token expired"
        
        return True, payload
    
    except Exception as e:
        return False, f"Token verification failed: {str(e)}"

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
            self.require_admin_auth(self.generate_license, data)
        
        elif path == "/admin/add-version":
            self.require_admin_auth(self.add_version, data)
        
        elif path == "/admin/generate-token":
            # Endpoint para gerar token admin (use com cuidado!)
            self.generate_token_endpoint(data)
        
        else:
            self.send_json({"error": "Not found"}, 404)
    
    # ========================================================================
    # AUTENTICAÇÃO
    # ========================================================================
    
    def require_admin_auth(self, callback, data):
        """
        Middleware: verifica Authorization header antes de executar callback
        """
        auth_header = self.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            self.send_json({"error": "Missing or invalid Authorization header"}, 401)
            return
        
        token = auth_header[7:]  # Remove "Bearer "
        is_valid, result = verify_admin_token(token)
        
        if not is_valid:
            self.send_json({"error": f"Authentication failed: {result}"}, 401)
            return
        
        # Token válido, executa callback
        callback(data)
    
    def generate_token_endpoint(self, data):
        """
        Endpoint especial para gerar token admin
        Requer: secret_key (senha para gerar token)
        """
        secret = data.get("secret_key", "")
        
        # Validação simples (em produção, use método mais robusto)
        if secret != ADMIN_SECRET_KEY:
            self.send_json({"error": "Invalid secret key"}, 403)
            return
        
        expires_in = data.get("expires_in", 86400)
        token = generate_admin_token(expires_in)
        
        self.send_json({
            "status": "success",
            "token": token,
            "expires_in": expires_in,
            "message": "Token generated successfully"
        })
    
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
    
    print(f"🔑 Admin secret key: {ADMIN_SECRET_KEY[:20]}...")
    print("💡 To generate admin token: POST /admin/generate-token with secret_key")
    
    server = HTTPServer(("0.0.0.0", 8000), APIHandler)
    print("🚀 ParkWash API running on http://0.0.0.0:8000")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
        server.server_close()