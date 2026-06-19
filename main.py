@"
import os
import psycopg2
from psycopg2 import sql
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid
from datetime import datetime
import hashlib

# Configuração
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://parkwash_user:xZkA1SWUYuwYUOZZMhfkGVVRdGYGI9JF@dpg-d8qj6rkvikkc73b18e6g-a/parkwash")

app = FastAPI()

# ============================================================================
# INICIALIZAÇÃO DO BANCO DE DADOS
# ============================================================================

def init_database():
    """Cria as tabelas se não existirem"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # Tabela de máquinas licenciadas
        cur.execute("""
            CREATE TABLE IF NOT EXISTS machines (
                id SERIAL PRIMARY KEY,
                mac_address VARCHAR(17) UNIQUE NOT NULL,
                license_key VARCHAR(64) UNIQUE NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_name VARCHAR(255),
                notes TEXT
            )
        """)
        
        # Tabela de versões
        cur.execute("""
            CREATE TABLE IF NOT EXISTS versions (
                id SERIAL PRIMARY KEY,
                version_number VARCHAR(10) UNIQUE NOT NULL,
                download_url VARCHAR(512) NOT NULL,
                changelog TEXT,
                released_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Tabela de logs de validação
        cur.execute("""
            CREATE TABLE IF NOT EXISTS validation_logs (
                id SERIAL PRIMARY KEY,
                mac_address VARCHAR(17),
                license_key VARCHAR(64),
                ip_address VARCHAR(45),
                status VARCHAR(20),
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

# Inicializa banco na primeira requisição
db_initialized = False

# ============================================================================
# MODELOS PYDANTIC
# ============================================================================

class LicenseValidationRequest(BaseModel):
    mac_address: str
    license_key: str

class LicenseValidationResponse(BaseModel):
    valid: bool
    message: str
    version: str = None
    download_url: str = None

class VersionResponse(BaseModel):
    version_number: str
    download_url: str
    changelog: str = None

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
def read_root():
    """Health check básico"""
    return {"status": "ParkWash API Online", "version": "1.0"}

@app.get("/health")
def health():
    """Health check detalhado"""
    return {"status": "online", "version": "1.0", "database": "connected"}

@app.post("/setup")
def setup_database():
    """Setup inicial - cria tabelas no banco de dados"""
    global db_initialized
    
    if init_database():
        db_initialized = True
        return {
            "status": "success",
            "message": "Database initialized successfully",
            "tables": ["machines", "versions", "validation_logs"]
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to initialize database")

@app.post("/license/validate", response_model=LicenseValidationResponse)
def validate_license(request: LicenseValidationRequest):
    """
    Valida licença de máquina
    Retorna: valid (bool), message (str), version e download_url da versão mais recente
    """
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        # Procura máquina
        cur.execute(
            "SELECT id, active FROM machines WHERE mac_address = %s AND license_key = %s",
            (request.mac_address, request.license_key)
        )
        machine = cur.fetchone()
        
        # Log da tentativa
        cur.execute(
            "INSERT INTO validation_logs (mac_address, license_key, status) VALUES (%s, %s, %s)",
            (request.mac_address, request.license_key, "valid" if machine else "invalid")
        )
        
        if machine:
            machine_id, is_active = machine
            
            if not is_active:
                conn.commit()
                cur.close()
                conn.close()
                return LicenseValidationResponse(
                    valid=False,
                    message="License is inactive"
                )
            
            # Atualiza last_check
            cur.execute(
                "UPDATE machines SET last_check = CURRENT_TIMESTAMP WHERE id = %s",
                (machine_id,)
            )
            
            # Busca versão mais recente
            cur.execute(
                "SELECT version_number, download_url, changelog FROM versions WHERE is_active = TRUE ORDER BY released_at DESC LIMIT 1"
            )
            version = cur.fetchone()
            
            conn.commit()
            cur.close()
            conn.close()
            
            if version:
                return LicenseValidationResponse(
                    valid=True,
                    message="License is valid",
                    version=version[0],
                    download_url=version[1]
                )
            else:
                return LicenseValidationResponse(
                    valid=True,
                    message="License is valid (no new version)"
                )
        else:
            conn.commit()
            cur.close()
            conn.close()
            return LicenseValidationResponse(
                valid=False,
                message="Invalid MAC address or license key"
            )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")

@app.get("/version/latest", response_model=VersionResponse)
def get_latest_version():
    """Retorna versão mais recente disponível"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        cur.execute(
            "SELECT version_number, download_url, changelog FROM versions WHERE is_active = TRUE ORDER BY released_at DESC LIMIT 1"
        )
        version = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if version:
            return VersionResponse(
                version_number=version[0],
                download_url=version[1],
                changelog=version[2] or ""
            )
        else:
            raise HTTPException(status_code=404, detail="No version found")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/admin/generate-license")
def generate_license(mac_address: str, client_name: str = ""):
    """
    ADMIN ONLY: Gera nova licença para máquina
    """
    try:
        # Gera license_key única
        license_key = hashlib.sha256(f"{mac_address}{uuid.uuid4()}".encode()).hexdigest()[:64]
        
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO machines (mac_address, license_key, client_name) VALUES (%s, %s, %s)",
            (mac_address, license_key, client_name)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "mac_address": mac_address,
            "license_key": license_key,
            "message": "License generated successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.post("/admin/add-version")
def add_version(version_number: str, download_url: str, changelog: str = ""):
    """
    ADMIN ONLY: Adiciona nova versão
    """
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO versions (version_number, download_url, changelog) VALUES (%s, %s, %s)",
            (version_number, download_url, changelog)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "version": version_number,
            "message": "Version added successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Executa ao iniciar a aplicação"""
    global db_initialized
    init_database()
    db_initialized = True

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
"@ | Out-File -Encoding UTF8 main.py