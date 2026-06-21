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

# --- Venda automática (Mercado Pago + e-mail) ------------------------------
MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "")
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")

PRODUTO_NOME = "Park & Wash — Licença Mensal"
PRODUTO_PRECO_PADRAO = 49.90  # ajuste aqui o valor padrão de venda
DOWNLOAD_URL_PRODUTO = "https://github.com/cmteleal01-cell/ParkWash-API/releases/download/v1.0.1/PARK_WASH_v1_0_1_Setup.exe"

venda_automatica_pronta = bool(MERCADOPAGO_ACCESS_TOKEN and MERCADOPAGO_WEBHOOK_SECRET)
email_pronto = bool(RESEND_API_KEY)

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
        # Nota: chaves novas do Supabase (sb_secret_..., sb_publishable_...)
        # NÃO são JWT e não devem ir no header Authorization: Bearer — isso
        # causa erro 403. O gateway do Supabase já traduz o "apikey" para o
        # papel correto internamente. Só "apikey" é necessário aqui.
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
# MERCADO PAGO — criar link de pagamento, validar webhook, buscar pagamento
# ============================================================================

def mp_request(method, path, body=None):
    """Chamada genérica à API do Mercado Pago, usando o Access Token."""
    if not MERCADOPAGO_ACCESS_TOKEN:
        return 0, {"error": "MERCADOPAGO_ACCESS_TOKEN não configurado"}

    url = f"https://api.mercadopago.com{path}"
    headers = {
        "Authorization": f"Bearer {MERCADOPAGO_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
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


def criar_link_pagamento(nome_cliente, email_cliente, valor):
    """
    Cria uma 'preference' no Mercado Pago (Checkout Pro) e devolve o link
    de pagamento para enviar ao cliente (WhatsApp, e-mail, etc).
    """
    referencia = str(uuid.uuid4())
    corpo = {
        "items": [{
            "title": PRODUTO_NOME,
            "quantity": 1,
            "unit_price": float(valor),
            "currency_id": "BRL",
        }],
        "payer": {"email": email_cliente, "name": nome_cliente} if email_cliente else {},
        "notification_url": "https://parkwash-api.onrender.com/webhook/mercadopago",
        "external_reference": referencia,
        "payment_methods": {
            "excluded_payment_types": [],
            "excluded_payment_methods": [],
        }
    }

    status, resultado = mp_request("POST", "/checkout/preferences", body=corpo)
    return status, resultado, referencia


def verificar_assinatura_mp(x_signature, x_request_id, data_id):
    """
    Valida a autenticidade da notificação do Mercado Pago.

    Formato do header x-signature: "ts=1234567890,v1=hash_hex"
    manifest = "id:{data_id};request-id:{x_request_id};ts:{ts};"
    Assinatura esperada = HMAC-SHA256(manifest, MERCADOPAGO_WEBHOOK_SECRET)

    Se isso não bater, a notificação NÃO veio do Mercado Pago — pode ser
    alguém forjando uma chamada tentando gerar licença de graça.
    """
    if not x_signature or not MERCADOPAGO_WEBHOOK_SECRET:
        return False

    ts = None
    v1 = None
    for parte in x_signature.split(","):
        if "=" not in parte:
            continue
        chave, valor = parte.split("=", 1)
        chave = chave.strip()
        valor = valor.strip()
        if chave == "ts":
            ts = valor
        elif chave == "v1":
            v1 = valor

    if not ts or not v1:
        return False

    manifest = f"id:{data_id};request-id:{x_request_id};ts:{ts};"
    assinatura_calculada = hmac.new(
        MERCADOPAGO_WEBHOOK_SECRET.encode(), manifest.encode(), hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(assinatura_calculada, v1)


def buscar_pagamento_mp(payment_id):
    """
    Busca o registro REAL e completo do pagamento na API do Mercado Pago.
    NUNCA confiamos no corpo do webhook para saber valor/status — só usamos
    o webhook como um "alguma coisa aconteceu, vá verificar" e sempre
    confirmamos a verdade direto na fonte.
    """
    return mp_request("GET", f"/v1/payments/{payment_id}")


def buscar_preapproval_mp(preapproval_id):
    """
    Busca o registro REAL de uma assinatura (preapproval) na API do MP.
    Usado quando o cliente cadastra o cartão e autoriza a assinatura.
    """
    return mp_request("GET", f"/preapproval/{preapproval_id}")


def buscar_authorized_payment_mp(authorized_payment_id):
    """
    Busca o registro REAL de uma cobrança recorrente (authorized_payment).
    Esse objeto contém o preapproval_id que liga essa cobrança mensal
    à assinatura original.
    """
    return mp_request("GET", f"/authorized_payments/{authorized_payment_id}")


# ============================================================================
# RESEND — envio automático de e-mail
# ============================================================================

def enviar_email_licenca(destinatario_email, destinatario_nome, license_key):
    """Envia e-mail automático com a chave de licença e o link de download."""
    if not RESEND_API_KEY:
        return False, "RESEND_API_KEY não configurado"

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto;">
        <h2 style="color:#2C3E6B;">Bem-vindo ao Park & Wash!</h2>
        <p>Olá, {destinatario_nome or 'cliente'}!</p>
        <p>Seu pagamento foi confirmado. Aqui está tudo que você precisa para começar:</p>
        <p><b>1. Baixe o instalador:</b><br>
           <a href="{DOWNLOAD_URL_PRODUTO}">{DOWNLOAD_URL_PRODUTO}</a></p>
        <p><b>2. Sua chave de licença:</b><br>
           <code style="background:#F4F6FB; padding:8px; display:inline-block; border-radius:4px;">{license_key}</code></p>
        <p>Durante a instalação, quando pedir a chave, cole exatamente o
           código acima. O manual completo do usuário está incluído
           automaticamente na instalação (atalho "Manual do Usuário" no
           menu Iniciar, junto com o programa).</p>
        <p>Qualquer dúvida, é só responder este e-mail.</p>
        <p style="color:#8FA3B1; font-size:12px;">Victoriae Sumus — Ad Maiora Semper</p>
    </div>
    """

    corpo = {
        "from": f"Victoriae Sumus <{RESEND_FROM_EMAIL}>",
        "to": [destinatario_email],
        "subject": "Sua licença Park & Wash chegou! 🅿️",
        "html": html,
    }

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    data = json.dumps(corpo).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return True, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return False, e.read().decode("utf-8")
    except Exception as e:
        return False, str(e)


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
        elif path == "/debug-log":
            # Serve o arquivo de log pra debug
            try:
                with open('/tmp/parkwash.log', 'r') as f:
                    content = f.read()
                self.send_json({"log": content}, 200)
            except FileNotFoundError:
                self.send_json({"log": "Arquivo de log não encontrado ainda"}, 200)
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        print(f"[POST] {self.path}")

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
        elif path == "/admin/criar-link-pagamento":
            self.require_admin_auth(self.criar_link_pagamento_endpoint, data)
        elif path == "/webhook/mercadopago":
            self.webhook_mercadopago(data)
        
        # --- Assinatura Recorrente ---
        elif path == "/pagamento/assinatura":
            try:
                email = data.get("email", "cliente@example.com")
                resultado = criar_preferencia_recorrente(email)
                self.send_json(resultado, 200)
            except Exception as e:
                self.send_json({"erro": str(e)}, 400)
        
        # --- Painel Admin Dashboard ---
        elif path.startswith("/admin/dashboard"):
            token = None
            if "?" in path:
                query_string = path.split("?")[1]
                params = {}
                for param in query_string.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        params[key] = urllib.parse.unquote(val)
                token = params.get("token")
            
            if token != ADMIN_SECRET_KEY:
                self.send_response(401)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h1>401 - Nao autorizado</h1>")
                return
            
            # Busca todas as licencas
            status_code, licencas = supabase_request("GET", "machines", {"select": "*"})
            
            if status_code != 200 or not licencas:
                licencas = []
            
            hoje = datetime.now()
            
            # Categoriza
            ativas = []
            vencendo = []
            atraso = []
            bloqueadas = []
            
            for lic in licencas:
                if not lic:
                    continue
                try:
                    venc = datetime.fromisoformat(lic.get("data_expiracao", ""))
                    dias = (venc - hoje).days
                    
                    status = lic.get("status", "desconhecido")
                    if status == "bloqueada":
                        bloqueadas.append(lic)
                    elif status == "atraso":
                        atraso.append(lic)
                    elif 0 < dias <= 3:
                        vencendo.append(lic)
                    elif dias > 0:
                        ativas.append(lic)
                    else:
                        bloqueadas.append(lic)
                except:
                    continue
            
            # Monta HTML
            html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Admin - Park & Wash</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #1e3a8a, #2563eb); color: white; padding: 20px; text-align: center; }}
        .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ font-size: 32px; font-weight: 700; color: #2563eb; }}
        .stat-card p {{ color: #666; margin-top: 5px; }}
        .table-section {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th {{ background: #f3f4f6; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
        td {{ padding: 12px; border-bottom: 1px solid #e5e7eb; }}
        .empty {{ text-align: center; color: #999; padding: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Painel Admin - Park & Wash</h1>
        <p>Última atualização: {hoje.strftime('%d/%m/%Y %H:%M:%S')}</p>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <h3>{len(ativas)}</h3>
                <p>Ativas</p>
            </div>
            <div class="stat-card">
                <h3>{len(vencendo)}</h3>
                <p>Vencendo em 3 dias</p>
            </div>
            <div class="stat-card">
                <h3>{len(atraso)}</h3>
                <p>Em Atraso</p>
            </div>
            <div class="stat-card">
                <h3>{len(bloqueadas)}</h3>
                <p>Bloqueadas</p>
            </div>
        </div>
        
        <div class="table-section">
            <h3>✅ Licenças Ativas ({len(ativas)})</h3>
            {gerar_tabela_admin_html(ativas) if ativas else '<p class="empty">Nenhuma licença ativa</p>'}
        </div>
        
        <div class="table-section">
            <h3>⏰ Vencendo em 3 dias ({len(vencendo)})</h3>
            {gerar_tabela_admin_html(vencendo) if vencendo else '<p class="empty">Nenhuma</p>'}
        </div>
        
        <div class="table-section">
            <h3>⚠️ Em Atraso ({len(atraso)})</h3>
            {gerar_tabela_admin_html(atraso) if atraso else '<p class="empty">Nenhuma</p>'}
        </div>
        
        <div class="table-section">
            <h3>🚫 Bloqueadas ({len(bloqueadas)})</h3>
            {gerar_tabela_admin_html(bloqueadas) if bloqueadas else '<p class="empty">Nenhuma</p>'}
        </div>
    </div>
</body>
</html>"""
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        
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
        status, resultado = supabase_request("GET", "machines", params={"limit": "1"})
        if status in (200, 206):
            self.send_json({"status": "success", "message": "Conexão com Supabase OK", "backend": "supabase"})
        else:
            self.send_json({
                "error": f"Falha ao conectar ao Supabase (status {status})",
                "detalhe_supabase": resultado,
                "url_usada": f"{SUPABASE_URL}/rest/v1/machines",
                "chave_configurada": bool(SUPABASE_KEY),
                "tamanho_chave": len(SUPABASE_KEY) if SUPABASE_KEY else 0,
            }, 500)

    # ------------------------------------------------------------------------
    # LICENCIAMENTO
    # ------------------------------------------------------------------------
    def validate_license(self, data):
        """
        Valida uma licença. mac_address e license_key são ambos obrigatórios
        no REQUEST do cliente (isso não muda) — mas a regra mudou do lado do
        servidor:

        - Licença existe e mac_address no banco está VAZIO (licença nunca
          usada) -> CLAIM: trava essa licença neste mac_address agora,
          considera válida. Isso é o que permite vender sem saber de
          antemão qual máquina o cliente vai usar.
        - Licença existe e mac_address no banco JÁ ESTÁ preenchido:
            - bate com o mac_address enviado agora -> válida (uso normal)
            - não bate -> inválida (alguém tentando usar a mesma chave em
              outra máquina — é exatamente o que queremos bloquear)
        - Licença não existe -> inválida.
        """
        # Log em arquivo
        with open('/tmp/parkwash.log', 'a') as f:
            f.write(f"[VALIDATE_LICENSE] Chamada! data={data}\n")
        
        mac_address = data.get("mac_address")
        license_key = data.get("license_key")
        
        with open('/tmp/parkwash.log', 'a') as f:
            f.write(f"[VALIDATE_LICENSE] license_key={license_key[:16] if license_key else None}... mac={mac_address}\n")
        if not mac_address or not license_key:
            self.send_json({"error": "Missing mac_address or license_key"}, 400)
            return

        # Busca SÓ por license_key — o mac_address da licença pode ainda
        # estar vazio (licença nunca usada) ou já ter um dono.
        
        with open('/tmp/parkwash.log', 'a') as f:
            f.write(f"[VALIDATE_LICENSE] Consultando Supabase com license_key={license_key[:16]}...\n")
        
        status, machines = supabase_request("GET", "machines", params={
            "license_key": f"eq.{license_key}",
            "select": "*"
        })
        
        with open('/tmp/parkwash.log', 'a') as f:
            f.write(f"[VALIDATE_LICENSE] Resposta Supabase: status={status}, machines={machines}\n")

        licenca_valida = False
        motivo_log = "invalid"

        if status == 200 and machines:
            machine = machines[0]
            mac_no_banco = machine.get("mac_address")

            if not machine.get("active", True):
                self.send_json({"valid": False, "message": "License is inactive"})
                self._log_validacao(mac_address, license_key, "inactive")
                return

            if not mac_no_banco:
                # Primeira vez que essa licença é usada — trava nesta máquina.
                supabase_request("PATCH", "machines",
                                  params={"id": f"eq.{machine['id']}"},
                                  body={"mac_address": mac_address, "last_check": agora_iso()})
                licenca_valida = True
                motivo_log = "claimed_first_use"

            elif mac_no_banco == mac_address:
                # Máquina já era a dona — validação normal do dia a dia.
                supabase_request("PATCH", "machines",
                                  params={"id": f"eq.{machine['id']}"},
                                  body={"last_check": agora_iso()})
                licenca_valida = True
                motivo_log = "valid"

            else:
                # Essa license_key já pertence a OUTRA máquina. Bloqueado.
                licenca_valida = False
                motivo_log = "mac_mismatch"

        self._log_validacao(mac_address, license_key, motivo_log)

        if licenca_valida:
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

    def _log_validacao(self, mac_address, license_key, status_str):
        try:
            supabase_request("POST", "validation_logs", body={
                "mac_address": mac_address, "license_key": license_key, "status": status_str
            })
        except Exception:
            pass

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
        """
        Gera uma licença nova. mac_address agora é OPCIONAL:
        - Se informado (uso manual/admin, como antes): licença já nasce
          travada nessa máquina.
        - Se omitido (fluxo automático de venda): licença nasce "sem dono"
          e trava na primeira vez que o cliente ativar — ver validate_license.
        """
        mac_address = data.get("mac_address") or None
        client_name = data.get("client_name", "")

        license_key = hashlib.sha256(f"{client_name}{uuid.uuid4()}".encode()).hexdigest()[:64]

        corpo = {"license_key": license_key, "client_name": client_name}
        if mac_address:
            corpo["mac_address"] = mac_address

        status, result = supabase_request(
            "POST", "machines", body=corpo,
            extra_headers={"Prefer": "return=representation"}
        )

        if status in (200, 201):
            self.send_json({
                "status": "success",
                "mac_address": mac_address,
                "license_key": license_key,
                "message": "License generated successfully"
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
    # VENDA AUTOMÁTICA — Mercado Pago + e-mail
    # ------------------------------------------------------------------------
    def criar_link_pagamento_endpoint(self, data):
        """
        ADMIN: gera um link de pagamento (Checkout Pro) para mandar a um
        lead por WhatsApp/Instagram. Não gera licença ainda — isso só
        acontece quando o pagamento for confirmado, via webhook.
        """
        if not venda_automatica_pronta:
            self.send_json({"error": "Mercado Pago não configurado no servidor "
                                       "(faltam MERCADOPAGO_ACCESS_TOKEN/MERCADOPAGO_WEBHOOK_SECRET)"}, 500)
            return

        nome_cliente = data.get("client_name", "")
        email_cliente = data.get("email", "")
        valor = data.get("valor", PRODUTO_PRECO_PADRAO)

        if not email_cliente:
            self.send_json({"error": "Missing email"}, 400)
            return

        status, resultado, referencia = criar_link_pagamento(nome_cliente, email_cliente, valor)

        if status in (200, 201) and resultado:
            self.send_json({
                "status": "success",
                "link_pagamento": resultado.get("init_point"),
                "link_pagamento_teste": resultado.get("sandbox_init_point"),
                "external_reference": referencia,
                "valor": valor,
                "message": "Envie o link_pagamento para o cliente. A licença será "
                           "gerada e enviada por e-mail automaticamente após a "
                           "confirmação do pagamento."
            })
        else:
            self.send_json({"error": f"Erro ao criar link no Mercado Pago: {resultado}"}, 500)

    def webhook_mercadopago(self, data):
        """
        Recebido automaticamente pelo Mercado Pago quando algo muda:
        - topic "payment": venda única (Pix avulso) — fluxo original.
        - topic "subscription_preapproval": cliente cadastrou cartão e
          autorizou a assinatura recorrente.
        - topic "subscription_authorized_payment": uma cobrança mensal
          específica da assinatura foi processada.

        Fluxo de segurança (igual para os 3 tipos):
        1. Valida a assinatura (x-signature) — rejeita se não vier do MP de fato.
        2. Busca o registro REAL na API do MP (nunca confia só no webhook).
        3. Idempotência via tabela pagamentos_processados.
        4. Sempre responde 200 rápido (MP reenvia se não receber 200).
        """
        print(f"[WEBHOOK] Recebido. path={self.path} body={data}")

        from urllib.parse import urlparse, parse_qs
        partes_url = urlparse(self.path)
        query = parse_qs(partes_url.query)

        data_id = query.get("data.id", [None])[0]
        if not data_id:
            data_id = (data.get("data") or {}).get("id")

        tipo_evento = query.get("type", [None])[0] or data.get("type") or data.get("topic") or "payment"
        print(f"[WEBHOOK] tipo_evento={tipo_evento}")

        x_signature = self.headers.get("x-signature")
        x_request_id = self.headers.get("x-request-id")
        print(f"[WEBHOOK] data_id={data_id} x_signature={x_signature} x_request_id={x_request_id}")

        if not verificar_assinatura_mp(x_signature, x_request_id, data_id):
            print("[WEBHOOK] Assinatura INVÁLIDA — descartando.")
            self.send_json({"received": True, "processado": False, "motivo": "assinatura_invalida"}, 200)
            return

        if not data_id:
            print("[WEBHOOK] Sem data_id — descartando.")
            self.send_json({"received": True, "processado": False, "motivo": "sem_payment_id"}, 200)
            return

        # --- Roteamento por tipo de evento ---
        if "authorized_payment" in tipo_evento:
            self._tratar_cobranca_recorrente(data_id)
            return
        elif "preapproval" in tipo_evento:
            self._tratar_assinatura_autorizada(data_id)
            return
        # else: cai no fluxo original de pagamento único (Pix avulso)

        # Idempotência: já processamos esse pagamento antes?
        status_check, ja_processados = supabase_request(
            "GET", "pagamentos_processados",
            params={"payment_id_mp": f"eq.{data_id}", "select": "id"}
        )
        print(f"[WEBHOOK] Checagem idempotência: status={status_check} ja_processados={ja_processados}")
        if status_check == 200 and ja_processados:
            self.send_json({"received": True, "processado": False, "motivo": "ja_processado_antes"}, 200)
            return

        # Busca o registro REAL do pagamento — fonte da verdade.
        status_pag, pagamento = buscar_pagamento_mp(data_id)
        print(f"[WEBHOOK] Pagamento real consultado: status_pag={status_pag} pagamento={pagamento}")

        if status_pag != 200 or not pagamento:
            self.send_json({"received": True, "processado": False, "motivo": "pagamento_nao_encontrado"}, 200)
            return

        if pagamento.get("status") != "approved":
            print(f"[WEBHOOK] Status não é approved: {pagamento.get('status')}")
            self.send_json({"received": True, "processado": False,
                             "motivo": f"status_{pagamento.get('status')}"}, 200)
            return

        payer = pagamento.get("payer") or {}
        email_comprador = payer.get("email") or ""
        nome_comprador = " ".join(filter(None, [payer.get("first_name"), payer.get("last_name")])).strip()
        valor_pago = pagamento.get("transaction_amount")

        # Gera a licença — sem mac_address, trava no primeiro uso real.
        license_key = hashlib.sha256(f"{email_comprador}{uuid.uuid4()}".encode()).hexdigest()[:64]
        status_lic, resultado_lic = supabase_request(
            "POST", "machines",
            body={"license_key": license_key, "client_name": nome_comprador or email_comprador},
            extra_headers={"Prefer": "return=representation"}
        )
        print(f"[WEBHOOK] Licença criada: status={status_lic} resultado={resultado_lic}")

        # Registra que esse pagamento já foi processado (evita duplicar se o
        # Mercado Pago reenviar a mesma notificação).
        supabase_request("POST", "pagamentos_processados", body={
            "payment_id_mp": str(data_id),
            "license_key": license_key,
            "email_comprador": email_comprador,
            "valor": valor_pago,
        })

        # Envia o e-mail automático — se falhar, registramos mas não
        # quebramos a resposta ao Mercado Pago (o pagamento já foi processado
        # e a licença já existe; o e-mail pode ser reenviado manualmente).
        email_enviado, detalhe_email = (False, "email_nao_configurado")
        if email_pronto and email_comprador:
            email_enviado, detalhe_email = enviar_email_licenca(email_comprador, nome_comprador, license_key)
        print(f"[WEBHOOK] E-mail: enviado={email_enviado} detalhe={detalhe_email}")

        self.send_json({
            "received": True,
            "processado": True,
            "license_key": license_key,
            "email_enviado": email_enviado,
        }, 200)


    def _tratar_assinatura_autorizada(self, preapproval_id):
        """
        Chamado quando o tópico do webhook é "subscription_preapproval".
        Quando o status virar "authorized", o cliente cadastrou o cartão
        e a assinatura está ativa — geramos a licença e liberamos acesso.
        """
        # Idempotência própria desse tipo de evento
        chave_idem = f"preapproval_{preapproval_id}"
        status_check, ja_processados = supabase_request(
            "GET", "pagamentos_processados",
            params={"payment_id_mp": f"eq.{chave_idem}", "select": "id"}
        )
        if status_check == 200 and ja_processados:
            self.send_json({"received": True, "processado": False, "motivo": "ja_processado_antes"}, 200)
            return

        status_pre, preapproval = buscar_preapproval_mp(preapproval_id)
        print(f"[WEBHOOK][preapproval] status_pre={status_pre} preapproval={preapproval}")

        if status_pre != 200 or not preapproval:
            self.send_json({"received": True, "processado": False, "motivo": "preapproval_nao_encontrado"}, 200)
            return

        if preapproval.get("status") != "authorized":
            print(f"[WEBHOOK][preapproval] Status não é authorized: {preapproval.get('status')}")
            self.send_json({"received": True, "processado": False,
                             "motivo": f"status_{preapproval.get('status')}"}, 200)
            return

        email_comprador = preapproval.get("payer_email") or ""

        # Já existe uma máquina/licença vinculada a este preapproval_id?
        status_existente, existentes = supabase_request(
            "GET", "machines", params={"preapproval_id": f"eq.{preapproval_id}", "select": "*"}
        )

        agora = datetime.now()
        novo_vencimento = (agora.replace(microsecond=0) + __import__("datetime").timedelta(days=30)).isoformat()

        if status_existente == 200 and existentes:
            # Já existia (ex.: reenvio do webhook) — apenas garante dados atualizados.
            license_key = existentes[0].get("license_key")
            supabase_request(
                "PATCH", "machines",
                params={"preapproval_id": f"eq.{preapproval_id}"},
                body={"data_expiracao": novo_vencimento, "status": "ativa", "email": email_comprador}
            )
        else:
            # Primeira autorização — cria a licença sem dono (trava no primeiro uso).
            license_key = hashlib.sha256(f"{email_comprador}{uuid.uuid4()}".encode()).hexdigest()[:64]
            supabase_request(
                "POST", "machines",
                body={
                    "license_key": license_key,
                    "client_name": email_comprador,
                    "email": email_comprador,
                    "preapproval_id": preapproval_id,
                    "data_expiracao": novo_vencimento,
                    "status": "ativa",
                },
                extra_headers={"Prefer": "return=representation"}
            )

        supabase_request("POST", "pagamentos_processados", body={
            "payment_id_mp": chave_idem,
            "license_key": license_key,
            "email_comprador": email_comprador,
            "valor": 119.90,
        })

        email_enviado, detalhe_email = (False, "email_nao_configurado")
        if email_pronto and email_comprador:
            email_enviado, detalhe_email = enviar_email_licenca(email_comprador, email_comprador, license_key)
        print(f"[WEBHOOK][preapproval] E-mail: enviado={email_enviado} detalhe={detalhe_email}")

        self.send_json({
            "received": True,
            "processado": True,
            "license_key": license_key,
            "email_enviado": email_enviado,
        }, 200)

    def _tratar_cobranca_recorrente(self, authorized_payment_id):
        """
        Chamado quando o tópico do webhook é "subscription_authorized_payment".
        Cada cobrança mensal da assinatura gera um evento desses — usamos
        para estender a data_expiracao da licença em +30 dias.
        """
        chave_idem = f"authpay_{authorized_payment_id}"
        status_check, ja_processados = supabase_request(
            "GET", "pagamentos_processados",
            params={"payment_id_mp": f"eq.{chave_idem}", "select": "id"}
        )
        if status_check == 200 and ja_processados:
            self.send_json({"received": True, "processado": False, "motivo": "ja_processado_antes"}, 200)
            return

        status_ap, authorized_payment = buscar_authorized_payment_mp(authorized_payment_id)
        print(f"[WEBHOOK][authorized_payment] status_ap={status_ap} dados={authorized_payment}")

        if status_ap != 200 or not authorized_payment:
            self.send_json({"received": True, "processado": False, "motivo": "cobranca_nao_encontrada"}, 200)
            return

        preapproval_id = authorized_payment.get("preapproval_id")
        pagamento_interno = authorized_payment.get("payment") or {}
        status_cobranca = pagamento_interno.get("status") or authorized_payment.get("status")

        if status_cobranca not in ("approved", "processed"):
            print(f"[WEBHOOK][authorized_payment] Cobrança não aprovada: {status_cobranca}")
            self.send_json({"received": True, "processado": False,
                             "motivo": f"status_{status_cobranca}"}, 200)
            return

        if not preapproval_id:
            self.send_json({"received": True, "processado": False, "motivo": "sem_preapproval_id"}, 200)
            return

        agora = datetime.now()
        novo_vencimento = (agora.replace(microsecond=0) + __import__("datetime").timedelta(days=30)).isoformat()

        status_machine, machine_atualizada = supabase_request(
            "PATCH", "machines",
            params={"preapproval_id": f"eq.{preapproval_id}"},
            body={"data_expiracao": novo_vencimento, "status": "ativa"},
            extra_headers={"Prefer": "return=representation"}
        )
        print(f"[WEBHOOK][authorized_payment] Renovação: status={status_machine} resultado={machine_atualizada}")

        supabase_request("POST", "pagamentos_processados", body={
            "payment_id_mp": chave_idem,
            "license_key": (machine_atualizada[0].get("license_key") if machine_atualizada else None),
            "email_comprador": (machine_atualizada[0].get("email") if machine_atualizada else None),
            "valor": authorized_payment.get("transaction_amount"),
        })

        self.send_json({
            "received": True,
            "processado": True,
            "preapproval_id": preapproval_id,
            "novo_vencimento": novo_vencimento,
        }, 200)


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

# ============================================================================
# ASSINATURA RECORRENTE (R$ 119,90/mês) — ADICIONE ISTO AO SEU main.py
# ============================================================================

def gerar_tabela_admin_html(licencas):
    """Gera HTML da tabela de licenças para o admin"""
    if not licencas:
        return ""
    
    linhas = ""
    for lic in licencas:
        email = lic.get("email", "N/A")
        venc = lic.get("data_expiracao", "N/A")
        status = lic.get("status", "N/A")
        
        linhas += f"""
        <tr>
            <td>{email}</td>
            <td>{venc}</td>
            <td><strong>{status}</strong></td>
        </tr>
        """
    
    return f"""
    <table>
        <thead>
            <tr>
                <th>Email</th>
                <th>Data de Vencimento</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>{linhas}</tbody>
    </table>
    """


def criar_preferencia_recorrente(email_cliente: str):
    """
    Cria assinatura recorrente REAL no Mercado Pago (cobrança automática via cartão)
    Usa a API correta: /preapproval (não /checkout/preferences)
    Valor: R$ 119,90/mês
    
    IMPORTANTE: Este modelo cobra via CARTÃO DE CRÉDITO automaticamente.
    O cliente cadastra o cartão uma vez na tela do Mercado Pago,
    e a cobrança acontece sozinha todo mês.
    """
    if not MERCADOPAGO_ACCESS_TOKEN:
        return {"erro": "Mercado Pago não configurado"}
    
    payload = {
        "reason": "Park & Wash - Assinatura Mensal",
        "external_reference": f"parkwash_recorrente_{datetime.now().timestamp()}",
        "payer_email": email_cliente,
        "back_url": "https://cmteleal01-cell.github.io/parkwash-landing",
        "auto_recurring": {
            "frequency": 1,
            "frequency_type": "months",
            "transaction_amount": 119.90,
            "currency_id": "BRL"
        },
        "status": "pending"
    }
    
    body_json = json.dumps(payload).encode('utf-8')
    
    url = "https://api.mercadopago.com/preapproval"
    req = urllib.request.Request(
        url,
        data=body_json,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {MERCADOPAGO_ACCESS_TOKEN}'
        }
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            dados = json.loads(response.read().decode('utf-8'))
            return {
                "preapproval_id": dados.get("id"),
                "init_point": dados.get("init_point"),
                "status": dados.get("status")
            }
    except urllib.error.HTTPError as e:
        # Captura o corpo real do erro retornado pelo Mercado Pago
        corpo_erro = e.read().decode('utf-8')
        return {"erro": f"Mercado Pago retornou {e.code}", "detalhes": corpo_erro}
    except Exception as e:
        return {"erro": str(e)}


# ============================================================================
# ROTAS PARA ASSINATURA
# ============================================================================

def handle_assinatura(path, method, body_str):
    """POST /pagamento/assinatura — Cria link de assinatura recorrente"""
    if method != "POST":
        return 405, {"erro": "Method not allowed"}
    
    try:
        body = json.loads(body_str) if body_str else {}
        email = body.get("email", "cliente@example.com")
        resultado = criar_preferencia_recorrente(email)
        return 200, resultado
    except Exception as e:
        return 400, {"erro": str(e)}


# ============================================================================
# PAINEL ADMIN — DASHBOARD
# ============================================================================

def gerar_dashboard_admin(token_admin: str):
    """
    Gera HTML do painel admin
    Mostra licenças ativas, vencimentos, atrasos, bloqueadas
    """
    
    if token_admin != ADMIN_SECRET_KEY:
        return 401, "Não autorizado"
    
    # Busca todas as licenças
    status_code, licencas = supabase_request("GET", "licencas", {"select": "*"})
    
    if status_code != 200 or not licencas:
        licencas = []
    
    hoje = datetime.now()
    
    # Categoriza
    ativas = []
    vencendo = []
    atraso = []
    bloqueadas = []
    
    for lic in licencas:
        if not lic:
            continue
        try:
            venc = datetime.fromisoformat(lic.get("data_expiracao", ""))
            dias = (venc - hoje).days
            
            status = lic.get("status", "desconhecido")
            if status == "bloqueada":
                bloqueadas.append(lic)
            elif status == "atraso":
                atraso.append(lic)
            elif 0 < dias <= 3:
                vencendo.append(lic)
            elif dias > 0:
                ativas.append(lic)
            else:
                bloqueadas.append(lic)
        except:
            continue
    
    # Monta HTML
    html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>Admin - Park & Wash</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; }}
            .header {{ background: linear-gradient(135deg, #1e3a8a, #2563eb); color: white; padding: 20px; text-align: center; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
            .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .stat-card h3 {{ font-size: 32px; font-weight: 700; color: #2563eb; }}
            .stat-card p {{ color: #666; margin-top: 5px; }}
            .table-section {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ background: #f3f4f6; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
            td {{ padding: 12px; border-bottom: 1px solid #e5e7eb; }}
            .status-ativo {{ color: #10b981; font-weight: 600; }}
            .status-vencendo {{ color: #f59e0b; font-weight: 600; }}
            .status-atraso {{ color: #ef4444; font-weight: 600; }}
            .status-bloqueada {{ color: #6b7280; font-weight: 600; }}
            .empty {{ text-align: center; color: #999; padding: 20px; }}
            @media (max-width: 768px) {{ .stats {{ grid-template-columns: repeat(2, 1fr); }} }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Painel Admin - Park & Wash</h1>
            <p>Última atualização: {hoje.strftime('%d/%m/%Y %H:%M:%S')}</p>
        </div>
        
        <div class="container">
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(ativas)}</h3>
                    <p>Ativas</p>
                </div>
                <div class="stat-card">
                    <h3>{len(vencendo)}</h3>
                    <p>Vencendo em 3 dias</p>
                </div>
                <div class="stat-card">
                    <h3>{len(atraso)}</h3>
                    <p>Em Atraso</p>
                </div>
                <div class="stat-card">
                    <h3>{len(bloqueadas)}</h3>
                    <p>Bloqueadas</p>
                </div>
            </div>
            
            <div class="table-section">
                <h3>✅ Licenças Ativas ({len(ativas)})</h3>
                {gerar_tabela_html(ativas) if ativas else '<p class="empty">Nenhuma licença ativa</p>'}
            </div>
            
            <div class="table-section">
                <h3>⏰ Vencendo em 3 dias ({len(vencendo)})</h3>
                {gerar_tabela_html(vencendo) if vencendo else '<p class="empty">Nenhuma</p>'}
            </div>
            
            <div class="table-section">
                <h3>⚠️ Em Atraso ({len(atraso)})</h3>
                {gerar_tabela_html(atraso) if atraso else '<p class="empty">Nenhuma</p>'}
            </div>
            
            <div class="table-section">
                <h3>🚫 Bloqueadas ({len(bloqueadas)})</h3>
                {gerar_tabela_html(bloqueadas) if bloqueadas else '<p class="empty">Nenhuma</p>'}
            </div>
        </div>
    </body>
    </html>
    """
    
    return 200, html


def gerar_tabela_html(licencas):
    """Gera HTML da tabela de licenças"""
    if not licencas:
        return ""
    
    linhas = ""
    for lic in licencas:
        email = lic.get("email", "N/A")
        venc = lic.get("data_expiracao", "N/A")
        status = lic.get("status", "N/A")
        
        linhas += f"""
        <tr>
            <td>{email}</td>
            <td>{venc}</td>
            <td><span class="status-{status}">{status}</span></td>
        </tr>
        """
    
    return f"""
    <table>
        <thead>
            <tr>
                <th>Email</th>
                <th>Data de Vencimento</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>{linhas}</tbody>
    </table>
    """


def handle_admin_dashboard(path, method, body_str, query_params):
    """GET /admin/dashboard?token=ADMIN_SECRET — Dashboard"""
    if method != "GET":
        return 405, {"erro": "Method not allowed"}
    
    token = query_params.get("token", [""])[0]
    status, html = gerar_dashboard_admin(token)
    
    if status == 401:
        return 401, "<h1>❌ Não autorizado</h1>"
    
    return 200, html


# ============================================================================
# EMAILS AUTOMÁTICOS
# ============================================================================

def enviar_email_aviso_vencimento(email_cliente: str, dias: int, vencimento: str):
    """Envia email avisando que licença vence em X dias"""
    if not RESEND_API_KEY:
        return False
    
    html = f"""
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e3a8a; color: white; padding: 20px; text-align: center;">
            <h1>⏰ Aviso Importante</h1>
        </div>
        <div style="background: #f9fafb; padding: 30px;">
            <p>Olá,</p>
            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
                <strong>Sua licença Park & Wash vencerá em {dias} dia(s)!</strong><br>
                Data de vencimento: <strong>{vencimento}</strong>
            </div>
            <p>Para continuar usando sem interrupções, renove agora:</p>
            <p><a href="https://parkwash-landing.github.io" style="display: inline-block; background: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600;">Renovar Licença</a></p>
            <p>Dúvidas? Entre em contato: cmte_leal@yahoo.com.br ou (11) 99999-7925</p>
        </div>
    </body>
    </html>
    """
    
    payload = {
        "from": "Park & Wash <onboarding@resend.dev>",
        "to": email_cliente,
        "subject": f"⏰ Sua licença vencerá em {dias} dia(s)",
        "html": html
    }
    
    try:
        body_json = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=body_json,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {RESEND_API_KEY}'
            }
        )
        
        with urllib.request.urlopen(req) as response:
            return response.status == 200
    except:
        return False


def verificar_licencas_vencimento():
    """
    Verifica licenças que vencerão em 3 dias
    Envia email de aviso
    Esta função deve ser chamada diariamente (ex: via cron job ou agendador)
    """
    status_code, licencas = supabase_request("GET", "licencas", {"select": "*"})
    
    if status_code != 200 or not licencas:
        return
    
    hoje = datetime.now()
    
    for lic in licencas:
        if not lic:
            continue
        
        try:
            venc = datetime.fromisoformat(lic.get("data_expiracao", ""))
            dias = (venc - hoje).days
            
            # Se faltam exatamente 3 dias E ainda não enviou email
            if dias == 3 and not lic.get("email_aviso_enviado"):
                email = lic.get("email")
                venc_str = lic.get("data_expiracao")
                
                if enviar_email_aviso_vencimento(email, 3, venc_str):
                    # Marca como enviado
                    supabase_request("PATCH", "licencas", 
                        {"id": f"eq.{lic['id']}"}, 
                        {"email_aviso_enviado": True})
        except:
            continue


# ============================================================================
# ADICIONE ISTO AO HANDLER PRINCIPAL (RequestHandler)
# ============================================================================
# 
# No seu do_GET e do_POST, adicione:
#
# elif path.startswith("/pagamento/assinatura"):
#     status, resp = handle_assinatura(path, "POST", body_str)
#     self.send_response(status)
#     self.send_header("Content-type", "application/json")
#     self.end_headers()
#     self.wfile.write(json.dumps(resp).encode())
#
# elif path.startswith("/admin/dashboard"):
#     status, html = handle_admin_dashboard(path, "GET", "", query_params)
#     self.send_response(status)
#     self.send_header("Content-type", "text/html; charset=utf-8")
#     self.end_headers()
#     self.wfile.write(html.encode('utf-8'))
#
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
