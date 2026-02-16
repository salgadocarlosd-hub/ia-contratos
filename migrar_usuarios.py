
import json, os
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en el entorno (.env).")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

USUARIOS = Path("usuarios.json")
CONFIGS = Path("configs.json")

usuarios = json.loads(USUARIOS.read_text(encoding="utf-8")) if USUARIOS.exists() else []
configs = json.loads(CONFIGS.read_text(encoding="utf-8")) if CONFIGS.exists() else {}

rows = []
for u in usuarios:
    username = u.get("username")
    if not username:
        continue
    cfg = configs.get(username, {})
    rows.append({
        "username": username,
        "password_hash": u.get("password_hash", ""),
        "empresa": cfg.get("empresa", ""),
        "rol": (cfg.get("rol") or "miembro"),
        "empresa_codigo": cfg.get("empresa_codigo", ""),
        "email_alertas": cfg.get("email_alertas", "")
    })

if not rows:
    print("No hay usuarios/configs que migrar.")
else:
    # upsert para no duplicar si lo ejecutas dos veces
    res = supabase.table("usuarios_app").upsert(rows, on_conflict="username").execute()
    print("Migrados:", len(res.data or []))
