import os
import uuid
import hashlib
import json
import hmac
import time
import base64
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "change_me_in_production_default_key_123")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

app_pronto = bool(SUPABASE_URL and SUPABASE_KEY)

# ============================================================================
# CLIENTE SUPABASE (via REST/PostgREST, só com urllib — zero dependências)
# ============================================================================

def supabase_request(method, table, params=None, body=None, extra_headers=None):
    """
    Faz uma requisição à API REST do Supabase (PostgREST).

    params: dict de filtros de query string, ex: {"mac_address": "eq.ABC", "select": "*"}
    body: dict (ou lista de dicts) para POST/PATCH
    Retorna: (status_code, dados_decodificados_ou_None)
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        return 0, {"error": "SUPABASE_URL/SUPABASE_KEY não configurados no servidor"}

    url = f"{SUPABASE_URL}/rest/v1/{table}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            corpo = resp.read().decode("utf-8")
            return resp.status, (json.loads(corpo) if corpo else None)
    except urllib.error.HTTPError as e:
        corpo_erro = e.read().decode("utf-8")
        try:
            return e.code, json.loads(corpo_erro)
        except Exception:
            return e.code, {"error": corpo_erro}
    except Exception as e:
        return 0, {"error": str(e)}


def agora_iso():
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# AUTENTICAÇÃO JWT (sem alteração — não depende de banco de dados)
# ============================================================================

def generate_admin_token(expires_in=86400):
    payload = {"iat": int(time.time()), "exp": int(time.time()) + expires_in, "role": "admin"}
    header = {"alg": "HS256", "typ": "JWT"}

    def base64_url_encode(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')

    header_encoded = base64_url_encode(header)
    payload_encoded = base64_url_encode(payload)
    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(ADMIN_SECRET_KEY.encode(), message.encode(), hashlib.sha256).digest()
    signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    return f"{message}.{signature_encoded}"


def verify_admin_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid token format"
        header_encoded, payload_encoded, signature_encoded = parts
        message = f"{header_encoded}.{payload_encoded}"
        payload_padded = payload_encoded + '=' * (4 - len(payload_encoded) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode())
        except Exception:
            return False, "Invalid token payload"

        expected_signature = hmac.new(ADMIN_SECRET_KEY.encode(), message.encode(), hashlib.sha256).digest()
        expected_signature_encoded = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')

        if signature_encoded != expected_signature_encoded:
            return False, "Invalid signature"
        if int(time.time()) > payload.get("exp", 0):
            return False, "Token expired"
        return True, payload
    except Exception as e:
        return False, f"Token verification failed: {str(e)}"


# ============================================================================
# HANDLER HTTP
# ============================================================================

class APIHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path

        if path == "/":
            self.send_json({"status": "ParkWash API Online", "version": "1.0", "backend": "supabase"})
        elif path == "/health":
            self.send_json({"status": "online", "version": "1.0", "database": "supabase" if app_pronto else "not_configured"})
        elif path == "/version/latest":
            self.get_latest_version()
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path

        content_length = int(self.headers.get('Content-Length', 0))
        body_raw = self.rfile.read(content_length).decode('utf-8')
        try:
            data = json.loads(body_raw) if body_raw else {}
        except Exception:
            data = {}

        if path == "/setup":
            self.testar_conexao_supabase()
        elif path == "/license/validate":
            self.validate_license(data)
        elif path == "/admin/generate-license":
            self.require_admin_auth(self.generate_license, data)
        elif path == "/admin/add-version":
            self.require_admin_auth(self.add_version, data)
        elif path == "/admin/generate-token":
            self.generate_token_endpoint(data)
        else:
            self.send_json({"error": "Not found"}, 404)

    # ------------------------------------------------------------------------
    # AUTENTICAÇÃO
    # ------------------------------------------------------------------------
    def require_admin_auth(self, callback, data):
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            self.send_json({"error": "Missing or invalid Authorization header"}, 401)
            return
        token = auth_header[7:]
        is_valid, result = verify_admin_token(token)
        if not is_valid:
            self.send_json({"error": f"Authentication failed: {result}"}, 401)
            return
        callback(data)

    def generate_token_endpoint(self, data):
        secret = data.get("secret_key", "")
        if secret != ADMIN_SECRET_KEY:
            self.send_json({"error": "Invalid secret key"}, 403)
            return
        expires_in = data.get("expires_in", 86400)
        token = generate_admin_token(expires_in)
        self.send_json({"status": "success", "token": token, "expires_in": expires_in,
                         "message": "Token generated successfully"})

    # ------------------------------------------------------------------------
    # DIAGNÓSTICO
    # ------------------------------------------------------------------------
    def testar_conexao_supabase(self):
        if not app_pronto:
            self.send_json({"error": "SUPABASE_URL/SUPABASE_KEY não configurados no Render"}, 500)
            return
        status, _ = supabase_request("GET", "machines", params={"limit": "1"})
        if status in (200, 206):
            self.send_json({"status": "success", "message": "Conexão com Supabase OK", "backend": "supabase"})
        else:
            self.send_json({"error": f"Falha ao conectar ao Supabase (status {status})"}, 500)

    # ------------------------------------------------------------------------
    # LICENCIAMENTO
    # ------------------------------------------------------------------------
    def validate_license(self, data):
        mac_address = data.get("mac_address")
        license_key = data.get("license_key")
        if not mac_address or not license_key:
            self.send_json({"error": "Missing mac_address or license_key"}, 400)
            return

        status, machines = supabase_request("GET", "machines", params={
            "mac_address": f"eq.{mac_address}",
            "license_key": f"eq.{license_key}",
            "select": "*"
        })

        # Log da tentativa — não bloqueia a resposta se o log falhar
        try:
            supabase_request("POST", "validation_logs", body={
                "mac_address": mac_address,
                "license_key": license_key,
                "status": "valid" if (status == 200 and machines) else "invalid"
            })
        except Exception:
            pass

        if status == 200 and machines:
            machine = machines[0]
            if not machine.get("active", True):
                self.send_json({"valid": False, "message": "License is inactive"})
                return

            supabase_request("PATCH", "machines",
                              params={"id": f"eq.{machine['id']}"},
                              body={"last_check": agora_iso()})

            v_status, versions = supabase_request("GET", "versions", params={
                "is_active": "eq.true", "order": "released_at.desc", "limit": "1", "select": "*"
            })
            if v_status == 200 and versions:
                v = versions[0]
                self.send_json({
                    "valid": True, "message": "License is valid",
                    "version": v["version_number"], "download_url": v["download_url"]
                })
            else:
                self.send_json({"valid": True, "message": "License is valid (no new version)"})
        else:
            self.send_json({"valid": False, "message": "Invalid MAC address or license key"})

    def get_latest_version(self):
        status, versions = supabase_request("GET", "versions", params={
            "is_active": "eq.true", "order": "released_at.desc", "limit": "1", "select": "*"
        })
        if status == 200 and versions:
            v = versions[0]
            self.send_json({
                "version_number": v["version_number"],
                "download_url": v["download_url"],
                "changelog": v.get("changelog") or ""
            })
        else:
            self.send_json({"error": "No version found"}, 404)

    def generate_license(self, data):
        mac_address = data.get("mac_address")
        client_name = data.get("client_name", "")
        if not mac_address:
            self.send_json({"error": "Missing mac_address"}, 400)
            return

        license_key = hashlib.sha256(f"{mac_address}{uuid.uuid4()}".encode()).hexdigest()[:64]

        status, result = supabase_request(
            "POST", "machines",
            body={"mac_address": mac_address, "license_key": license_key, "client_name": client_name},
            extra_headers={"Prefer": "return=representation"}
        )

        if status in (200, 201):
            self.send_json({
                "status": "success", "mac_address": mac_address,
                "license_key": license_key, "message": "License generated successfully"
            })
        else:
            self.send_json({"error": f"Erro ao gravar no Supabase (status {status}): {result}"}, 500)

    def add_version(self, data):
        version_number = data.get("version_number")
        download_url = data.get("download_url")
        changelog = data.get("changelog", "")
        if not version_number or not download_url:
            self.send_json({"error": "Missing version_number or download_url"}, 400)
            return

        status, result = supabase_request(
            "POST", "versions",
            body={"version_number": version_number, "download_url": download_url, "changelog": changelog},
            extra_headers={"Prefer": "return=representation"}
        )

        if status in (200, 201):
            self.send_json({"status": "success", "version": version_number,
                             "message": "Version added successfully"})
        else:
            self.send_json({"error": f"Erro ao gravar no Supabase (status {status}): {result}"}, 500)

    # ------------------------------------------------------------------------
    # UTILIDADES
    # ------------------------------------------------------------------------
    def send_json(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def log_message(self, format, *args):
        pass


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if not app_pronto:
        print("⚠️  AVISO: SUPABASE_URL ou SUPABASE_KEY não configurados — API vai responder erro em rotas de banco.")
    else:
        print("✅  Conectado ao Supabase (configuração detectada).")

    server = HTTPServer(("0.0.0.0", 8000), APIHandler)
    print("🚀 ParkWash API running on http://0.0.0.0:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
        server.server_close()
