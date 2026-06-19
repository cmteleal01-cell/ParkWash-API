import os
import sqlite3
from flask import Flask, jsonify, request
import uuid
import hashlib

# Configuração
DATABASE_FILE = "parkwash.db"

app = Flask(__name__)

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
# ENDPOINTS
# ============================================================================

@app.route("/", methods=["GET"])
def read_root():
    """Health check básico"""
    return jsonify({"status": "ParkWash API Online", "version": "1.0"})

@app.route("/health", methods=["GET"])
def health():
    """Health check detalhado"""
    return jsonify({"status": "online", "version": "1.0", "database": "connected"})

@app.route("/setup", methods=["POST"])
def setup_database():
    """Setup inicial - cria tabelas no banco de dados"""
    if init_database():
        return jsonify({
            "status": "success",
            "message": "Database initialized successfully",
            "tables": ["machines", "versions", "validation_logs"]
        })
    else:
        return jsonify({"error": "Failed to initialize database"}), 500

@app.route("/license/validate", methods=["POST"])
def validate_license():
    """
    Valida licença de máquina
    Retorna: valid (bool), message (str), version e download_url da versão mais recente
    """
    try:
        data = request.get_json()
        mac_address = data.get("mac_address")
        license_key = data.get("license_key")
        
        if not mac_address or not license_key:
            return jsonify({"error": "Missing mac_address or license_key"}), 400
        
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
                return jsonify({
                    "valid": False,
                    "message": "License is inactive"
                })
            
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
                return jsonify({
                    "valid": True,
                    "message": "License is valid",
                    "version": version[0],
                    "download_url": version[1]
                })
            else:
                return jsonify({
                    "valid": True,
                    "message": "License is valid (no new version)"
                })
        else:
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({
                "valid": False,
                "message": "Invalid MAC address or license key"
            })
    
    except Exception as e:
        return jsonify({"error": f"Validation error: {str(e)}"}), 500

@app.route("/version/latest", methods=["GET"])
def get_latest_version():
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
            return jsonify({
                "version_number": version[0],
                "download_url": version[1],
                "changelog": version[2] or ""
            })
        else:
            return jsonify({"error": "No version found"}), 404
    
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500

@app.route("/admin/generate-license", methods=["POST"])
def generate_license():
    """
    ADMIN ONLY: Gera nova licença para máquina
    """
    try:
        data = request.get_json()
        mac_address = data.get("mac_address")
        client_name = data.get("client_name", "")
        
        if not mac_address:
            return jsonify({"error": "Missing mac_address"}), 400
        
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
        
        return jsonify({
            "status": "success",
            "mac_address": mac_address,
            "license_key": license_key,
            "message": "License generated successfully"
        })
    
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500

@app.route("/admin/add-version", methods=["POST"])
def add_version():
    """
    ADMIN ONLY: Adiciona nova versão
    """
    try:
        data = request.get_json()
        version_number = data.get("version_number")
        download_url = data.get("download_url")
        changelog = data.get("changelog", "")
        
        if not version_number or not download_url:
            return jsonify({"error": "Missing version_number or download_url"}), 400
        
        conn = sqlite3.connect(DATABASE_FILE)
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO versions (version_number, download_url, changelog) VALUES (?, ?, ?)",
            (version_number, download_url, changelog)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "status": "success",
            "version": version_number,
            "message": "Version added successfully"
        })
    
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500

# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

if __name__ == "__main__":
    init_database()
    app.run(host="0.0.0.0", port=8000, debug=False)