from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from postgrest.exceptions import APIError
from pathlib import Path
from pypdf import PdfReader

from datetime import datetime, timezone
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, HTTPException
from pydantic import BaseModel
from typing import Optional

import re
import json
from fastapi import Header, HTTPException
import re, json, os
from urllib.parse import quote
import jwt
import logging
from datetime import timezone
from datetime import datetime, timedelta
from dateutil import parser

from fastapi import Request
from passlib.context import CryptContext
import yagmail

from fastapi.responses import StreamingResponse
import csv
from io import StringIO

import secrets
import string

from fastapi.responses import JSONResponse
from supabase import Client
from io import BytesIO
from supabase import create_client
from dotenv import load_dotenv

import requests
import base64
import os

load_dotenv()


# -----------------------------
# App + templates + session
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("contractai")

app = FastAPI()
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret")

# Detectar entorno
ENV = (os.environ.get("ENV") or "local").lower()
IS_PROD = ENV in ("prod", "production")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=IS_PROD,   # 🔐 True solo en producción
    same_site="lax"
)

SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").strip()
SUPABASE_SERVICE_ROLE_KEY = (os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
SUPABASE_ANON_KEY = (os.environ.get("SUPABASE_ANON_KEY") or "").strip()

CRON_SECRET = os.environ.get("CRON_SECRET")

supabase_service = None
supabase_anon = None

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase_service = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

if SUPABASE_URL and SUPABASE_ANON_KEY:
    supabase_anon = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
else:
    print("⚠️ SUPABASE_URL o SUPABASE_ANON_KEY no están configuradas en el entorno.")

# ✅ alias DESPUÉS de crear el cliente
storage_client = supabase_service
# supabase apunta al service_role (NO RLS). Evitar usarlo para queries de usuario.
supabase = supabase_service


if SUPABASE_URL and not SUPABASE_URL.startswith("https://"):
    print("⚠️ SUPABASE_URL no empieza por https://")

BUCKET = "contratos"
MAX_PDF_SIZE = 20 * 1024 * 1024  # 20MB

templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


CARPETA_DOCS = Path("docs")
CARPETA_DOCS.mkdir(exist_ok=True)

class EntidadCreate(BaseModel):
    tipo: str                 # "vehiculo", "subcontrata", etc.
    nombre: str               # display
    codigo: Optional[str] = None  # matrícula/CIF/código interno
    metadata: Optional[dict] = None
    activo: Optional[bool] = True

# -----------------------------
# Helpers: auth
# -----------------------------
def usuario_actual(request: Request):
    return request.session.get("user")


def insertar_usuario_db(username: str, password_hash: str, rol: str = "admin"):
    if supabase is None:
        raise RuntimeError("Supabase no disponible")
    supabase.table("usuarios_app").insert({
        "username": username,
        "password_hash": password_hash,
        "empresa": "",
        "rol": rol,
        "empresa_codigo": "",
        "email_alertas": ""
    }).execute()


def username_a_email(username: str) -> str:
    u = (username or "").strip().lower()
    # dominio interno (no real) solo para Supabase Auth
    return f"{u}@users.tuapp.local"


def supabase_user_client(request: Request):
    """
    Devuelve un cliente anon con el access_token del usuario.
    Si el token caducó, intenta refrescar con refresh_token guardado en sesión.
    """
    token = request.session.get("sb_access_token")
    if not token:
        return None

    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

    try:
        client.postgrest.auth(token)
        return client
    except Exception as e:
        # Si falla por JWT expirado, intentamos refresh
        if "JWT expired" in str(e) or "PGRST303" in str(e):
            refresh_token = request.session.get("sb_refresh_token")
            if not refresh_token or supabase_anon is None:
                return None

            try:
                # refrescar sesión
                refreshed = supabase_anon.auth.refresh_session(refresh_token)

                session_obj = getattr(refreshed, "session", None) or (
                    refreshed.get("session") if isinstance(refreshed, dict) else None
                )
                new_access = getattr(session_obj, "access_token", None) if session_obj else None
                new_refresh = getattr(session_obj, "refresh_token", None) if session_obj else None

                if not new_access:
                    return None

                request.session["sb_access_token"] = new_access
                if new_refresh:
                    request.session["sb_refresh_token"] = new_refresh

                # reintentar auth
                client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                client.postgrest.auth(new_access)
                return client
            except:
                return None

        return None


def normalizar_password(p: str) -> str:
    """
    bcrypt limita 72 BYTES (no caracteres).
    Esto quita saltos raros/espacios y corta a 72 bytes utf-8.
    """
    if p is None:
        p = ""
    p = str(p).replace("\r", "").replace("\n", "").strip()
    b = p.encode("utf-8")[:72]
    return b.decode("utf-8", errors="ignore")


def normalizar_empresa(nombre: str) -> str:
    # Mantiene el formato que ya estás usando como “verdad”
    # (puedes cambiar la lógica luego a slug si quieres)
    return (nombre or "").strip()


def crear_usuario(username: str, password: str):
    username = (username or "").strip()
    if not username:
        return False

    if supabase is None:
        raise RuntimeError("Supabase no disponible")

    if obtener_usuario_db(username):
        return False

    password = normalizar_password(password)
    insertar_usuario_db(username, pwd_context.hash(password), rol="admin")
    return True



def validar_usuario(username: str, password: str):
    u = obtener_usuario_db(username)
    if not u:
        return False

    password = normalizar_password(password)
    return pwd_context.verify(password, u.get("password_hash", ""))



# -----------------------------
# Helpers: usuario/config en Supabase (usuarios_app)
# -----------------------------
def obtener_usuario_db(username: str):
    if supabase is None:
        return None
    res = supabase.table("usuarios_app").select("*").eq("username", username).limit(1).execute()
    return (res.data or [None])[0]


def get_email_alertas(username: str):
    u = obtener_usuario_db(username)
    return (u or {}).get("email_alertas")


def set_email_alertas(username: str, email: str):
    if supabase is None:
        return
    supabase.table("usuarios_app").update({"email_alertas": (email or "").strip()}).eq("username", username).execute()


def get_empresa(username: str):
    u = obtener_usuario_db(username)
    return (u or {}).get("empresa", "") or ""


def set_empresa(username: str, empresa: str):
    if supabase is None:
        return
    empresa_clean = normalizar_empresa(empresa)
    supabase.table("usuarios_app").update({"empresa": empresa_clean}).eq("username", username).execute()



def get_rol(username: str) -> str:
    u = obtener_usuario_db(username)
    rol = ((u or {}).get("rol") or "").strip().lower()
    if rol not in ("admin", "miembro"):
        rol = "admin"
        if supabase is not None:
            supabase.table("usuarios_app").update({"rol": rol}).eq("username", username).execute()
    return rol


def set_rol(username: str, rol: str):
    rol = (rol or "").strip().lower()
    if rol not in ("admin", "miembro"):
        rol = "miembro"
    if supabase is None:
        return
    supabase.table("usuarios_app").update({"rol": rol}).eq("username", username).execute()



def get_empresa_codigo(username: str):
    u = obtener_usuario_db(username)
    return (u or {}).get("empresa_codigo", "") or ""


def set_empresa_codigo(username: str, codigo: str):
    if supabase is None:
        return
    supabase.table("usuarios_app").update({"empresa_codigo": (codigo or "").strip().upper()}).eq("username", username).execute()


def generar_codigo_empresa():
    alfabeto = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alfabeto) for _ in range(6))


def obtener_empresa_db(empresa_id: str):
    if supabase is None or not empresa_id:
        return None
    res = supabase.table("empresas").select("*").eq("id", empresa_id).limit(1).execute()
    return (res.data or [None])[0]


def get_empresa_id(username: str):
    u = obtener_usuario_db(username) or {}
    eid = u.get("empresa_id")
    if not eid:
        return None
    return str(eid)


def set_empresa_id(username: str, empresa_id: str):
    if supabase is None:
        return
    supabase.table("usuarios_app").update({"empresa_id": empresa_id}).eq("username", username).execute()


def buscar_empresa_por_codigo(codigo: str):
    if supabase is None:
        return None
    codigo = (codigo or "").strip().upper()
    res = supabase.table("empresas").select("*").eq("codigo", codigo).limit(1).execute()
    return (res.data or [None])[0]


# -----------------------------
# Helpers: auditoría (audit_log)
# -----------------------------
ALLOWED_ACTIONS = {
    "upload", "delete", "restore", "purge",
    "config_update", "download",
    "alert_sent",
    "notification_sent",
    "status_change",
    "responsable_change",
    "create",
    "evidencia_added",
    "update"  # ✅ necesario para evidencia
}

ALLOWED_ENTITY_TYPES = {
    "contratos", "contratos_papelera", "config",
    "obligaciones", "notificaciones",
    "entidades_reguladas",
    "vehiculos"              # opcional si lo quieres
}


def outbox_insert_notificacion(
    sb,
    empresa_id: str,
    canal: str,
    destinatarios: list[str],
    tipo_aviso: str,
    metadata: dict,
    dedupe_key: str,
    obligacion_id: str | None = None,
):
    """
    Inserta en notificaciones (outbox) haciendo fan-out:
    1 destinatario = 1 fila.
    Si dedupe_key ya existe => no rompe.
    Devuelve: número de filas creadas.
    """

    # Normaliza + dedupe + separa inválidos
    validos, invalidos = normalizar_destinatarios(destinatarios or [])

    md_base = dict(metadata or {})
    md_base["dq"] = {
        "destinatarios_original": destinatarios or [],
        "destinatarios_validos": validos,
        "destinatarios_invalidos": invalidos,
        "dedupe_aplicado": True,
        "fanout": True,
    }

    # Si no hay válidos, insertamos una fila en error (permanente) para auditoría
    if not validos:
        payload_err = {
            "empresa_id": empresa_id,
            "obligacion_id": obligacion_id,
            "tipo_aviso": tipo_aviso,
            "canal": canal,
            "destinatarios": [],
            "status": NOTIF_STATUS_ERROR,
            "metadata": md_base,
            "dedupe_key": f"{dedupe_key}:no_valid_destinatarios",
            "error": "No valid destinatarios (prevalidation)",
            "provider": "resend",
            "provider_id": None,
        }
        try:
            sb.table("notificaciones").insert(payload_err).execute()
        except Exception as e:
            msg = str(e).lower()
            if "duplicate" in msg or "23505" in msg:
                return 0
            raise
        return 1

    creadas = 0

    for d in validos:
        payload = {
            "empresa_id": empresa_id,
            "obligacion_id": obligacion_id,
            "tipo_aviso": tipo_aviso,
            "canal": canal,
            "destinatarios": [d],  # fan-out: 1 por fila
            "status": NOTIF_STATUS_PENDING,
            "metadata": md_base,
            # dedupe por destinatario
            "dedupe_key": f"{dedupe_key}:{d}",
        }

        try:
            sb.table("notificaciones").insert(payload).execute()
            creadas += 1
        except Exception as e:
            msg = str(e).lower()
            if "duplicate" in msg or "23505" in msg:
                continue
            raise

    return creadas

# -----------------------------
# Constantes de estados (evita strings sueltos)
# -----------------------------
OBL_ESTADOS_ABIERTOS = ("pendiente", "en_proceso", "incumplida")
OBL_ESTADO_RESUELTA = "resuelta"

NOTIF_STATUS_PENDING = "pending"
NOTIF_STATUS_SENT = "sent"
NOTIF_STATUS_ERROR = "error"
NOTIF_STATUS_PROCESSING = "processing"

def get_auth_user_id_from_session(request: Request) -> str | None:
    """
    Extrae el auth_user_id (sub) del token de Supabase guardado en sesión.
    No verifica firma: suficiente para auditoría interna.
    """
    token = request.session.get("sb_access_token")
    if not token:
        return None
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("sub")
    except Exception:
        return None


def log_event(
    sb,
    empresa_id: str,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    metadata: dict | None = None,
    request: Request | None = None
):
    """
    Inserta un registro de auditoría usando el cliente del usuario (sb) -> respeta RLS.
    """
    if not sb or not empresa_id:
        return

    action = (action or "").strip()
    entity_type = (entity_type or "").strip()

    # Evitar violar constraints
    if action not in ALLOWED_ACTIONS:
        logger.warning("audit_log: action no permitida: %s", action)
        return
    if entity_type not in ALLOWED_ENTITY_TYPES:
        logger.warning("audit_log: entity_type no permitido: %s", entity_type)
        return

    actor_username = None
    actor_auth_id = None
    if request is not None:
        actor_username = request.session.get("user")
        actor_auth_id = get_auth_user_id_from_session(request)

    try:
        sb.table("audit_log").insert({
            "empresa_id": empresa_id,
            "actor_auth_id": actor_auth_id,
            "actor_username": actor_username,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "metadata": metadata or {}
        }).execute()
    except Exception as e:
        logger.warning("audit_log insert falló: %s", str(e)[:160])

# -----------------------------
# Helpers: jobs (job_runs)
# -----------------------------
def job_run_start(job_name: str, metadata: dict | None = None) -> int | None:
    """
    Registra inicio de job en job_runs (solo service_role).
    Devuelve job_run_id.
    """
    if supabase_service is None:
        return None
    try:
        now = utc_now_iso()
        r = supabase_service.table("job_runs").insert({
            "job_name": job_name,
            "status": "started",
            "started_at": now,          # ✅ importante
            "metadata": metadata or {}
        }).execute()
        row = (r.data or [None])[0]
        return row.get("id") if row else None
    except Exception as e:
        logger.warning("job_runs start falló: %s", str(e)[:160])
        return None


def job_run_finish(
    job_run_id: int | None,
    status: str,
    metadata: dict | None = None,
    started_at: datetime | None = None
):
    """
    Cierra el job_run. status: success|error
    """
    if supabase_service is None or not job_run_id:
        return
    try:
        finished = datetime.utcnow()
        duration_ms = None
        if started_at:
            duration_ms = int((finished - started_at).total_seconds() * 1000)

        payload = {
            "status": status,
            "finished_at": finished.isoformat(),
            "metadata": metadata or {}
        }
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms

        supabase_service.table("job_runs").update(payload).eq("id", job_run_id).execute()
    except Exception as e:
        logger.warning("job_runs finish falló: %s", str(e)[:160])


# -----------------------------
# Helpers: políticas por empresa/tipo (enterprise)
# -----------------------------
def get_empresa_politica(empresa_id: str) -> dict:
    """
    Lee politica general por empresa (service_role).
    Devuelve defaults si no existe.
    """
    defaults = {
        "antispam_horas": 24,
        "notificar_desde": None,
        "notificar_hasta": None,
        "dias_laborables": None,  # [1..7] o None
        "tz": "Europe/Madrid",
    }
    if not empresa_id or supabase_service is None:
        return defaults

    try:
        res = (
            supabase_service.table("empresa_politicas")
            .select("antispam_horas,notificar_desde,notificar_hasta,dias_laborables,tz")
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        return {**defaults, **(row or {})}
    except Exception as e:
        logger.warning("get_empresa_politica fallo empresa_id=%s err=%s", empresa_id, str(e)[:120])
        return defaults


def get_obligacion_politica(empresa_id: str, tipo: str | None):
    """
    Devuelve política por empresa y tipo.
    Fallback escalable:
      1) tipo específico
      2) tipo='general'
      3) defaults
    """
    if supabase_service is None or not empresa_id:
        return {
            "recordatorios_dias": [30],
            "escalar_si_criticidad_alta": False,
            "escalar_a_rol": None,
            "sla_dias_antes": None,
        }

    tipo_in = (tipo or "").strip().lower() or None

    defaults = {
        "recordatorios_dias": [30],
        "escalar_si_criticidad_alta": False,
        "escalar_a_rol": None,
        "sla_dias_antes": None,
    }

    def merge(row: dict | None):
        if not row:
            return None
        out = dict(defaults)

        rd = row.get("recordatorios_dias")
        if rd is not None:
            out["recordatorios_dias"] = rd

        out["escalar_si_criticidad_alta"] = bool(row.get("escalar_si_criticidad_alta")) if row.get("escalar_si_criticidad_alta") is not None else defaults["escalar_si_criticidad_alta"]
        out["escalar_a_rol"] = row.get("escalar_a_rol", defaults["escalar_a_rol"])
        out["sla_dias_antes"] = row.get("sla_dias_antes", defaults["sla_dias_antes"])
        return out

    # 1) Intentar tipo específico
    if tipo_in:
        r1 = (
            supabase_service
            .table("obligacion_politicas")
            .select("recordatorios_dias,escalar_si_criticidad_alta,escalar_a_rol,sla_dias_antes")
            .eq("empresa_id", empresa_id)
            .eq("tipo", tipo_in)
            .limit(1)
            .execute()
        )
        row1 = (r1.data or [None])[0]
        pol1 = merge(row1)
        if pol1:
            return pol1

    # 2) Fallback a general
    r2 = (
        supabase_service
        .table("obligacion_politicas")
        .select("recordatorios_dias,escalar_si_criticidad_alta,escalar_a_rol,sla_dias_antes")
        .eq("empresa_id", empresa_id)
        .eq("tipo", "general")
        .limit(1)
        .execute()
    )
    row2 = (r2.data or [None])[0]
    pol2 = merge(row2)
    if pol2:
        return pol2

    # 3) Defaults
    return defaults

def calcular_score_entidad(obligaciones: list) -> tuple[int, dict]:
    """
    Score 0-100. Conservador y explicable.
    Usa criticidad_snapshot + fechas + SLA.
    """
    hoy = utc_now().date()

    def parse_date(x):
        if not x:
            return None
        try:
            return parser.parse(str(x)).date()
        except Exception:
            return None

    def crit(o):
        return (o.get("criticidad_snapshot") or "media").lower()

    abiertas = [o for o in obligaciones if o.get("estado") != "resuelta"]

    vencida_crit = 0
    vencida_alta = 0
    prox7_crit = 0
    prox30_crit = 0
    prox7_alta = 0
    fuera_sla_crit = 0
    fuera_sla_alta = 0
    abiertas_crit = 0
    abiertas_alta = 0

    for o in abiertas:
        c = crit(o)
        fl = parse_date(o.get("fecha_limite"))

        if c == "critica":
            abiertas_crit += 1
        elif c == "alta":
            abiertas_alta += 1

        if o.get("incumple_sla") is True:
            if c == "critica":
                fuera_sla_crit += 1
            elif c == "alta":
                fuera_sla_alta += 1

        if fl:
            if fl < hoy:
                if c == "critica":
                    vencida_crit += 1
                elif c == "alta":
                    vencida_alta += 1
            else:
                if c == "critica" and fl <= hoy + timedelta(days=7):
                    prox7_crit += 1
                if c == "critica" and fl <= hoy + timedelta(days=30):
                    prox30_crit += 1
                if c == "alta" and fl <= hoy + timedelta(days=7):
                    prox7_alta += 1

    score = 100

    # Penalizaciones operativas fuertes
    score -= 40 * vencida_crit
    score -= 25 * vencida_alta
    score -= 20 * fuera_sla_crit
    score -= 10 * fuera_sla_alta

    # Penalizaciones temporales
    score -= 25 * prox7_crit
    score -= 10 * prox30_crit
    score -= 10 * prox7_alta

    # Penalizaciones estructurales (disciplina)
    score -= 3 * abiertas_crit
    score -= 2 * abiertas_alta

    # Clamp
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    breakdown = {
        "abiertas_total": len(abiertas),
        "abiertas_crit": abiertas_crit,
        "abiertas_alta": abiertas_alta,
        "vencida_crit": vencida_crit,
        "vencida_alta": vencida_alta,
        "prox7_crit": prox7_crit,
        "prox30_crit": prox30_crit,
        "prox7_alta": prox7_alta,
        "fuera_sla_crit": fuera_sla_crit,
        "fuera_sla_alta": fuera_sla_alta,
    }

    return score, breakdown

def recalcular_score_y_notificar_entidad(sb, empresa_id: str, entidad_id: str):
    """
    1) Lee obligaciones entidad
    2) Calcula score + nivel
    3) Inserta snapshot en entidad_scores
    4) Si cambió el nivel vs último snapshot => inserta notificación (outbox) con dedupe + cooldown
    """
    # 1) Leer obligaciones
    res = (
        sb.table("obligaciones")
        .select("id,estado,fecha_limite,incumple_sla,criticidad_snapshot")
        .eq("empresa_id", empresa_id)
        .eq("entidad_id", entidad_id)
        .execute()
    )
    obls = res.data or []

    # 2) Calcular
    calc = calcular_scores_entidad_v1(obls)

    score = calc["score_regulatorio"]
    nivel = calc["nivel_regulatorio"]
    breakdown = calc["breakdown"]
    estado_final = calc["estado_final"]
    score_ops = calc["score_operativo"]
    nivel_ops = calc["nivel_operativo"]
    razones = calc["razones"]
    modelo_version = calc["modelo_version"]

    # 3) Leer último snapshot (si existe)
    prev = (
        sb.table("entidad_scores")
        .select("score,nivel,calculado_en")
        .eq("empresa_id", empresa_id)
        .eq("entidad_id", entidad_id)
        .order("calculado_en", desc=True)
        .limit(1)
        .execute()
    )
    prev_row = (prev.data or [None])[0]
    prev_nivel = prev_row.get("nivel") if prev_row else None

    # 4) Insert snapshot actual
    sb.table("entidad_scores").insert({
        "empresa_id": empresa_id,
        "entidad_id": entidad_id,
        "score": score,
        "nivel": nivel,
        "breakdown": breakdown,
        "origen": "event",
    }).execute()

    # 5) Policy
    pol_res = (
        sb.table("score_notif_policies")
        .select("enabled,notify_on_level_change,cooldown_minutes,destinos")
        .eq("empresa_id", empresa_id)
        .eq("scope", "entidad")
        .limit(1)
        .execute()
    )
    pol = (pol_res.data or [None])[0] or {}
    if not pol.get("enabled", True):
        return

    if not pol.get("notify_on_level_change", True):
        return

    # Si no había nivel previo, NO notifiques (evita spam al inicializar)
    if prev_nivel is None:
        return

    # Solo notifica si cambió el nivel
    if nivel == prev_nivel:
        return

    cooldown = int(pol.get("cooldown_minutes") or 180)
    destinos = pol.get("destinos") or []
    if not destinos:
        return

    # 6) Cooldown: si ya notificamos recientemente para esta entidad y este nivel, no repetir
    # dedupe_key fija por "nivel nuevo" (evita duplicados)
    dedupe_key = f"score:entidad:{entidad_id}:nivel:{nivel}"

    # Si quieres cooldown por cualquier cambio de nivel, usa una clave más general:
    # dedupe_key = f"score:entidad:{entidad_id}:nivel_change"

    # Buscar si ya hubo notificación reciente con misma dedupe_key
    # (si tu tabla notificaciones tiene created_at o creado_en, usa el correcto)
    since_iso = (datetime.utcnow() - timedelta(minutes=cooldown)).isoformat()

    recent = (
        sb.table("notificaciones")
        .select("id")
        .eq("empresa_id", empresa_id)
        .eq("dedupe_key", dedupe_key)
        .gte("creado_en", since_iso)  # ⚠️ si tu columna se llama distinto, cambia aquí
        .limit(1)
        .execute()
    )
    if (recent.data or []):
        return

    # 7) Insert outbox (tu job ya se encarga de enviar)
    sb.table("notificaciones").insert({
        "empresa_id": empresa_id,
        "obligacion_id": None,  # porque esto es por entidad/score, no por una obligación concreta
        "tipo_aviso": "score_entidad_nivel",
        "canal": "email",
        "destinatarios": destinos,
        "status": "pending",
        "metadata": {
            "entidad_id": entidad_id,
            "nivel_anterior": prev_nivel,
            "nivel_nuevo": nivel,
            "score": score,
            "breakdown": breakdown
        },
        "dedupe_key": dedupe_key
    }).execute()


SCORING_VERSION = "v1"

def nivel_por_score(score: int) -> str:
    if score >= 90:
        return "EXCELENTE"
    if score >= 75:
        return "CONTROLADO"
    if score >= 50:
        return "RIESGO"
    return "CRITICO"


def calcular_scores_entidad_v1(obligaciones: list) -> dict:
    hoy = utc_now().date()

    def parse_date(x):
        if not x:
            return None
        try:
            return parser.parse(str(x)).date()
        except Exception:
            return None

    def crit(o):
        return (o.get("criticidad_snapshot") or "media").lower()

    abiertas = [o for o in obligaciones if o.get("estado") != "resuelta"]

    vencida_crit = vencida_alta = 0
    prox7_crit = prox30_crit = prox7_alta = 0
    fuera_sla_crit = fuera_sla_alta = 0
    abiertas_crit = abiertas_alta = 0

    for o in abiertas:
        c = crit(o)
        fl = parse_date(o.get("fecha_limite"))

        if c == "critica":
            abiertas_crit += 1
        elif c == "alta":
            abiertas_alta += 1

        if o.get("incumple_sla") is True:
            if c == "critica":
                fuera_sla_crit += 1
            elif c == "alta":
                fuera_sla_alta += 1

        if fl:
            if fl < hoy:
                if c == "critica":
                    vencida_crit += 1
                elif c == "alta":
                    vencida_alta += 1
            else:
                if c == "critica" and fl <= hoy + timedelta(days=7):
                    prox7_crit += 1
                if c == "critica" and fl <= hoy + timedelta(days=30):
                    prox30_crit += 1
                if c == "alta" and fl <= hoy + timedelta(days=7):
                    prox7_alta += 1

    # --- score regulatorio ---
    score_reg = 100
    score_reg -= 35 * vencida_crit
    score_reg -= 20 * vencida_alta
    score_reg -= 15 * fuera_sla_crit
    score_reg -= 8 * fuera_sla_alta
    score_reg -= 20 * prox7_crit
    score_reg -= 8 * prox30_crit
    score_reg -= 8 * prox7_alta
    score_reg = max(0, min(100, score_reg))

    # --- score operativo ---
    abiertas_total = len(abiertas)
    score_ops = 100
    score_ops -= 4 * abiertas_crit
    score_ops -= 2 * abiertas_alta
    score_ops -= 1 * abiertas_total
    score_ops = max(0, min(100, score_ops))

    nivel_reg = nivel_por_score(score_reg)
    nivel_ops = nivel_por_score(score_ops)

    # --- estado final (conservador) ---
    if vencida_crit > 0 or score_reg < 50:
        estado_final = "BLOQUEADO"
    elif prox7_crit > 0 or score_reg < 75:
        estado_final = "EN_RIESGO"
    else:
        estado_final = "EN_CONTROL"

    # razones explicables (top)
    razones = []
    if vencida_crit: razones.append(f"{vencida_crit} crítica(s) vencida(s)")
    if vencida_alta: razones.append(f"{vencida_alta} alta(s) vencida(s)")
    if prox7_crit: razones.append(f"{prox7_crit} crítica(s) vencen en 7d")
    if fuera_sla_crit: razones.append(f"{fuera_sla_crit} crítica(s) fuera de SLA")
    if abiertas_crit >= 3: razones.append(f"{abiertas_crit} críticas abiertas")
    if not razones:
        razones.append("Sin riesgos inmediatos detectados")

    breakdown = {
        "abiertas_total": abiertas_total,
        "abiertas_crit": abiertas_crit,
        "abiertas_alta": abiertas_alta,
        "vencida_crit": vencida_crit,
        "vencida_alta": vencida_alta,
        "prox7_crit": prox7_crit,
        "prox30_crit": prox30_crit,
        "prox7_alta": prox7_alta,
        "fuera_sla_crit": fuera_sla_crit,
        "fuera_sla_alta": fuera_sla_alta,
    }

    return {
        "modelo_version": SCORING_VERSION,
        "score_regulatorio": score_reg,
        "nivel_regulatorio": nivel_reg,
        "score_operativo": score_ops,
        "nivel_operativo": nivel_ops,
        "estado_final": estado_final,
        "razones": razones[:5],
        "breakdown": breakdown
    }

def _destinatarios_default(sb, empresa_id: str):
    """
    Destinatarios por defecto (defendible):
    - emails de admins con email_alertas configurado
    """
    if not sb or not empresa_id:
        return []

    admins = (
        sb.table("usuarios_app")
        .select("email_alertas")
        .eq("empresa_id", empresa_id)
        .eq("rol", "admin")
        .execute()
    )

    destinos = [
        (r.get("email_alertas") or "").strip()
        for r in (admins.data or [])
        if (r.get("email_alertas") or "").strip()
    ]
    # dedupe
    return sorted(list(set(destinos)))

from datetime import datetime, timedelta, date

def generar_recordatorios_obligaciones(
    sb: Client,
    empresa_id: str,
    dias_antes_list: list[int] = [30, 7, 1],
    canal: str = "email",
):
    """
    Genera notificaciones en outbox (tabla notificaciones) para obligaciones próximas a vencer.

    - NO envía emails aquí (solo inserta pending).
    - Idempotente vía dedupe_key estable (por evento).
    - Si no hay destinatarios (admins con email), no genera nada y devuelve reason.
    """

    hoy = utc_now().date()

    # Destinatarios por defecto (admins con email_alertas)
    destinatarios = _destinatarios_default(sb, empresa_id)
    if not destinatarios:
        # BUGFIX: antes había un `continue` inválido (no hay loop)
        return {"ok": True, "creadas": 0, "saltadas": 0, "reason": "no_destinatarios"}

    # Normaliza lista de días
    dias_antes_set = set()
    for d in dias_antes_list or []:
        try:
            dias_antes_set.add(int(d))
        except Exception:
            pass

    if not dias_antes_set:
        return {"ok": True, "creadas": 0, "saltadas": 0, "reason": "dias_antes_vacio"}

    # Rango de fechas a consultar (hasta el máximo lookahead)
    max_lookahead = max(dias_antes_set)
    fecha_hasta = hoy + timedelta(days=max_lookahead)

    # Traer obligaciones en rango
    resp = (
        sb.table("obligaciones")
        .select("id, empresa_id, fecha_limite, estado, responsable_auth_id, titulo, tipo")
        .eq("empresa_id", empresa_id)
        .gte("fecha_limite", str(hoy))
        .lte("fecha_limite", str(fecha_hasta))
        .execute()
    )
    rows = resp.data or []

    creadas = 0
    saltadas = 0

    for ob in rows:
        obligacion_id = ob.get("id")
        if not obligacion_id:
            continue

        # Parse fecha_limite -> date
        try:
            fl_date = datetime.fromisoformat(str(ob.get("fecha_limite"))[:10]).date()
        except Exception:
            continue

        dias_restantes = (fl_date - hoy).days
        if dias_restantes not in dias_antes_set:
            continue

        # Construcción profesional dedupe_key (POR EVENTO, NO por "hoy")
        tipo_aviso = f"{dias_restantes}d"
        dedupe_key = f"{tipo_aviso}:{canal}:{obligacion_id}:{fl_date.isoformat()}"

        metadata = {
            "obligacion_id": str(obligacion_id),
            "fecha_limite": fl_date.isoformat(),
            "dias_restantes": dias_restantes,
            "estado": ob.get("estado"),
            "responsable_auth_id": ob.get("responsable_auth_id"),
            "titulo": ob.get("titulo"),
            "tipo": ob.get("tipo"),
        }

        # Inserta en outbox (idempotente por dedupe_key)
        inserted = outbox_insert_notificacion(
            sb=sb,
            empresa_id=str(empresa_id),
            canal=canal,
            destinatarios=destinatarios,
            tipo_aviso=tipo_aviso,
            metadata=metadata,
            dedupe_key=dedupe_key,
            obligacion_id=str(obligacion_id),
        )

        if inserted:
            creadas += 1
        else:
            saltadas += 1

    return {"ok": True, "creadas": creadas, "saltadas": saltadas}


# -----------------------------
# Helpers: registro contratos
# -----------------------------
def extraer_texto_pdf(ruta_pdf):
    """
    Lee PDF normal. Si sale casi vacío, intenta OCR (PDF escaneado).
    """
    try:
        reader = PdfReader(ruta_pdf)
        texto = ""

        for pagina in reader.pages:
            texto += pagina.extract_text() or ""

        if len(texto.strip()) < 50:
            import pytesseract
            from pdf2image import convert_from_path

            paginas = convert_from_path(ruta_pdf)
            texto = ""
            for pagina in paginas:
                texto += pytesseract.image_to_string(pagina, lang="spa")

        return texto

    except Exception as e:
        print("Error leyendo PDF:", e)
        return ""


def extraer_texto_pdf_bytes(pdf_bytes: bytes) -> str:
    try:
        reader = PdfReader(BytesIO(pdf_bytes))
        texto = ""
        for pagina in reader.pages:
            texto += pagina.extract_text() or ""
        return texto
    except Exception as e:
        print("Error leyendo PDF bytes:", e)
        return ""


def extraer_fecha_fin(texto: str):
    t = " ".join(texto.split())
    claves = r"(fecha\s*(de)?\s*(finalizaci[oó]n|fin)|finalizaci[oó]n|vencimiento|vigencia\s*hasta|caduca|expira)"
    fecha = r"(\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4})"

    patrones = [
        rf"{claves}\s*[:\-]?\s*{fecha}",
        rf"{claves}\s*(del\s*contrato)?\s*[:\-]?\s*{fecha}",
        rf"{fecha}\s*{claves}",
    ]

    for pat in patrones:
        m = re.search(pat, t, flags=re.IGNORECASE)
        if m:
            fecha_raw = m.group(m.lastindex)
            try:
                dt = parser.parse(fecha_raw, dayfirst=True)
                return dt.date().isoformat()
            except:
                pass

    return None


def extraer_fechas(texto: str):
    patrones = r"\b(\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4})\b"
    halladas = re.findall(patrones, texto)
    fechas = []
    for f in halladas:
        try:
            dt = parser.parse(f, dayfirst=True)
            fechas.append(dt.date().isoformat())
        except:
            pass
    return sorted(list(set(fechas)))


def clasificar_contrato(texto: str):
    t = texto.lower()

    reglas = {
        "alquiler": ["arrendamiento", "alquiler", "arrendador"],
        "seguro": ["seguro", "aseguradora", "póliza"],
        "servicios": ["prestación de servicios", "servicios profesionales"],
        "laboral": ["contrato de trabajo", "empleado", "empresa"],
        "préstamo": ["préstamo", "financiación", "interés"]
    }

    for tipo, palabras in reglas.items():
        if any(p in t for p in palabras):
            return tipo

    return "otro"


def obtener_contratos_supabase(sb, empresa_id: str, limit: int = 200):
    if sb is None:
        return []
    res = (
        sb.table("contratos")
        .select("archivo_pdf,fecha_fin,tipo,owner,creado_en,storage_path")
        .eq("empresa_id", empresa_id)
        .order("creado_en", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data or []


def obtener_alertas_supabase(sb, empresa_id: str, dias: int = 30, limit: int = 500):
    """
    Alertas (<= hoy + dias) usando RLS (sb).
    """
    if sb is None or not empresa_id:
        return []

    hoy = datetime.now().date()
    limite = hoy + timedelta(days=dias)

    try:
        res = (
            sb.table("contratos")
            .select("archivo_pdf,fecha_fin,tipo,owner,creado_en,storage_path,empresa_id")
            .eq("empresa_id", empresa_id)
            .order("fecha_fin", desc=False)
            .limit(limit)
            .execute()
        )
    except Exception:
        return []

    items = res.data or []

    alertas = []
    for it in items:
        fecha = it.get("fecha_fin")
        if not fecha:
            continue

        try:
            fin = datetime.fromisoformat(str(fecha)).date()
        except Exception:
            continue

        if fin <= limite:
            alertas.append({
                "owner": it.get("owner"),
                "archivo_pdf": it.get("archivo_pdf"),
                "tipo": it.get("tipo", "otro"),
                "vence_el": str(fecha)[:10],
                "dias_restantes": (fin - hoy).days,
                "storage_path": it.get("storage_path", "")
            })

    alertas.sort(key=lambda x: x["vence_el"])
    return alertas


@app.get("/exportar_excel")
def exportar_excel(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    empresa_id = get_empresa_id(user)

    auth_user_id = get_auth_user_id_from_session(request)

    query = (
        sb.table("contratos")
        .select("archivo_pdf,tipo,fecha_fin,owner")
        .eq("empresa_id", empresa_id)
    )

    if get_rol(user) != "admin":
        query = query.eq("owner_auth_id", auth_user_id)

    res = query.execute()


    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Archivo","Tipo","Fecha fin","Responsable"])

    for row in res.data or []:
        writer.writerow([
            row.get("archivo_pdf"),
            row.get("tipo"),
            row.get("fecha_fin"),
            row.get("owner")
        ])

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=contratos.csv"}
    )

# -----------------------------
# Auth pages
# -----------------------------
@app.get("/login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    username = (username or "").strip()
    if not username:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Username requerido"})

    if supabase_anon is None:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Supabase no disponible"})

    email_interno = username_a_email(username)
    password = normalizar_password(password)

    try:
        login_res = supabase_anon.auth.sign_in_with_password({"email": email_interno, "password": password})
        session_obj = getattr(login_res, "session", None) or (login_res.get("session") if isinstance(login_res, dict) else None)
        access_token = getattr(session_obj, "access_token", None) if session_obj else None
        refresh_token = getattr(session_obj, "refresh_token", None) if session_obj else None


        if not access_token:
            return templates.TemplateResponse("login.html", {"request": request, "error": "No se pudo iniciar sesión (token vacío)"})

        # sesión de tu app
        request.session["user"] = username
        # token Supabase para RLS
        request.session["sb_access_token"] = access_token
        if refresh_token:
            request.session["sb_refresh_token"] = refresh_token


        return RedirectResponse(url="/", status_code=303)

    except Exception:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Usuario o contraseña incorrectos"})


@app.get("/debug_me")
def debug_me(request: Request):
    token = request.session.get("sb_access_token")
    if not token:
        return {"ok": False, "error": "No token en sesión"}

    # OJO: esto es SOLO para debug (no verifica firma)
    decoded = jwt.decode(token, options={"verify_signature": False})

    return {
        "ok": True,
        "auth_user_id": decoded.get("sub"),
        "email": decoded.get("email"),
        "role": decoded.get("role"),
    }

@app.get("/landing")
async def landing(request: Request):
    return templates.TemplateResponse("landing.html", {
        "request": request
    })



# -----------------------------
# Registro
# -----------------------------
@app.get("/registro")
def registro_get(request: Request):
    return templates.TemplateResponse("registro.html", {"request": request, "error": None})


@app.post("/registro")
def registro_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    codigo_empresa: str = Form("")
):
    username = (username or "").strip()

    password = normalizar_password(password)

    # Validación contraseña mínima
    if len(password) < 8:
        return templates.TemplateResponse("registro.html", {
           "request": request,
           "error": "La contraseña debe tener al menos 8 caracteres"
        })

        # Validación básica username
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", username):
            return templates.TemplateResponse("registro.html", {
                "request": request,
                "error": "El usuario solo puede contener letras, números o '_' (3-30 caracteres)"
            })

    if not username:
        return templates.TemplateResponse("registro.html", {"request": request, "error": "Username requerido"})

    if supabase_anon is None or supabase_service is None:
        return templates.TemplateResponse("registro.html", {"request": request, "error": "Supabase no disponible"})

    email_interno = username_a_email(username)
    password = normalizar_password(password)

    # 1) Crear usuario en Supabase Auth (con email interno)
    try:
        auth_res = supabase_anon.auth.sign_up({"email": email_interno, "password": password})
        user_obj = getattr(auth_res, "user", None) or (auth_res.get("user") if isinstance(auth_res, dict) else None)
        if not user_obj:
            return templates.TemplateResponse("registro.html", {"request": request, "error": "No se pudo crear el usuario (Auth)"})
        auth_user_id = user_obj.id
    except Exception as e:
        return templates.TemplateResponse("registro.html", {"request": request, "error": f"Error creando usuario: {str(e)[:160]}"})

    # 2) Crear fila en usuarios_app con auth_user_id
    try:
        # determinar rol/empresa según código
        empresa_id = None
        rol = "admin"
        codigo = (codigo_empresa or "").strip().upper()

        mensaje_registro = None

        if codigo:
            empresa_row = buscar_empresa_por_codigo(codigo)
            if empresa_row:
                empresa_id = empresa_row["id"]
                rol = "miembro"
                mensaje_registro = f"Te has unido a {empresa_row['nombre']} como miembro"
            else:
                return templates.TemplateResponse("registro.html", {
                    "request": request,
                    "error": "El código de empresa no existe"
                })
        else:
            # CREAR EMPRESA AUTOMÁTICAMENTE
            nombre_empresa = username  # puedes cambiar esto luego

            res_new = supabase_service.table("empresas").insert({
                "nombre": nombre_empresa
            }).execute()

            new_row = (res_new.data or [None])[0]
            if not new_row:
                return templates.TemplateResponse("registro.html", {
                    "request": request,
                    "error": "No se pudo crear la empresa"
                })

            empresa_id = new_row["id"]

            # Generar código empresa
            codigo_generado = generar_codigo_empresa()

            supabase_service.table("empresas").update({
                "codigo": codigo_generado
            }).eq("id", empresa_id).execute()

            rol = "admin"
            mensaje_registro = "Se ha creado tu empresa y eres administrador"


        supabase_service.table("usuarios_app").insert({
            "username": username,
            "password_hash": pwd_context.hash(password),   # puedes mantenerlo o quitarlo luego
            "auth_user_id": auth_user_id,
            "rol": rol,
            "empresa_id": empresa_id,
            "email_alertas": ""
        }).execute()
    except Exception as e:
        return templates.TemplateResponse("registro.html", {"request": request, "error": f"Error creando perfil: {str(e)[:160]}"})

    # 3) Iniciar sesión en tu app (y además guardar token de Supabase)
    try:
        login_res = supabase_anon.auth.sign_in_with_password({"email": email_interno, "password": password})
        session_obj = getattr(login_res, "session", None) or (login_res.get("session") if isinstance(login_res, dict) else None)

        access_token = getattr(session_obj, "access_token", None) if session_obj else None
        refresh_token = getattr(session_obj, "refresh_token", None) if session_obj else None

        if access_token:
            request.session["sb_access_token"] = access_token
        if refresh_token:
            request.session["sb_refresh_token"] = refresh_token

    except:
        # si falla el login automático, igual lo dejamos registrado
        pass

    if mensaje_registro:
        request.session["flash_msg"] = mensaje_registro

    request.session["user"] = username
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


DEBUG = (os.environ.get("DEBUG", "0") == "1")

@app.get("/__debug_session")
def debug_session(request: Request):
    if not DEBUG:
        return RedirectResponse(url="/", status_code=303)
    return JSONResponse({"session": dict(request.session)})

# -----------------------------
# Dashboard
# -----------------------------
@app.get("/")
def dashboard(request: Request, tipo: str = None):

    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    # --- Parámetros ---
    ok = request.query_params.get("ok")
    err = request.query_params.get("err")
    hoy = datetime.now().date()
    hoy_str = hoy.isoformat()

    if err:
        mensaje = f"❌ Error: {err}"
    elif ok == "1":
        mensaje = "Contrato subido y procesado ✅"
    else:
        mensaje = None

    flash_msg = request.session.pop("flash_msg", None)

    rol = get_rol(user)
    empresa_id = get_empresa_id(user)
    email_alertas = get_email_alertas(user)
    auth_user_id = get_auth_user_id_from_session(request)

    empresa_row = obtener_empresa_db(empresa_id) if empresa_id else None

            # ✅ Actividad reciente (audit_log)
    actividad = []
    try:
        rlog = (
            sb.table("audit_log")
            .select("created_at,actor_username,action,entity_type,entity_id,metadata")
            .eq("empresa_id", empresa_id)
            .order("created_at", desc=True)
            .limit(20)
            .execute()
        )
        actividad = rlog.data or []
    except Exception:
        actividad = []

    # 🔒 Forzar configuración si admin no completó datos
    if rol == "admin":
        if not empresa_id or not empresa_row or not empresa_row.get("nombre") or not email_alertas:
            return RedirectResponse(url="/config?force=1", status_code=303)

    # --- Query contratos (RLS) ---
    try:
        query = (
            sb.table("contratos")
            .select("id,archivo_pdf,fecha_fin,tipo,creado_en,owner,owner_auth_id,storage_path")
            .eq("empresa_id", empresa_id)
        )

        if rol != "admin":
            if not auth_user_id:
                request.session.clear()
                return RedirectResponse(url="/login", status_code=303)
            query = query.eq("owner_auth_id", auth_user_id)

        res = query.order("creado_en", desc=True).limit(200).execute()
        items = res.data or []

    except Exception as e:
        if "JWT" in str(e):
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": user,
            "rol": rol,
            "mensaje": f"❌ Error consultando contratos: {str(e)[:140]}",
            "flash_msg": flash_msg,
            "hoy": hoy_str,
            "stats": {"total": 0, "proximos": 0, "vencidos": 0, "sin_fecha": 0, "fuera_sla": 0},
            "todos": [],
            "ultimos": [],
            "vencen_30": [],
            "vencen_7": [],
            "vencidos_list": [],
            "sin_fecha_list": [],
            "miembros": [],
            "grafico_labels": [],
            "grafico_values": [],
            "tipo_actual": None,
            "actividad": actividad
        })

    # --- Filtro por tipo ---
    tipos_validos = ["laboral", "alquiler", "servicios", "seguro", "otro"]
    if tipo and tipo in tipos_validos:
        items = [i for i in items if (i.get("tipo") or "otro") == tipo]
    else:
        tipo = None

    # --- Helpers ---
    limite_30 = hoy + timedelta(days=30)
    limite_7 = hoy + timedelta(days=7)

    def to_date(x):
        try:
            return datetime.fromisoformat(str(x)[:10]).date()
        except:
            return None

    # --- Listas ---
    todos = []
    vencen_30 = []
    vencen_7 = []
    vencidos_list = []
    sin_fecha_list = []

    for it in items:
        fin = to_date(it.get("fecha_fin"))

        row = {
            "id": it.get("id"),
            "archivo_pdf": it.get("archivo_pdf") or "",
            "tipo": it.get("tipo") or "otro",
            "fecha_fin": fin.isoformat() if fin else None,  # <-- string YYYY-MM-DD o None
            "owner": it.get("owner") or "",
            "storage_path": it.get("storage_path") or "",
        }

        todos.append(row)

        if not fin:
            sin_fecha_list.append(row)
            continue

        if fin < hoy:
            vencidos_list.append(row)

        if fin <= limite_30:
            vencen_30.append({**row, "dias": (fin - hoy).days})

        if fin <= limite_7:
            vencen_7.append({**row, "dias": (fin - hoy).days})

    # ---------------------------------------------------------
    # ✅ KPI Obligaciones (ESCALABLE): leer desde la VISTA
    #     kpi_obligaciones_empresa
    # ---------------------------------------------------------
    fuera_sla = 0
    total_obligaciones = 0
    abiertas = 0

    try:
        rkpi = (
            sb.table("kpi_obligaciones_empresa")
            .select("total_obligaciones,abiertas,fuera_sla_abiertas")
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        k = (rkpi.data or [None])[0] or {}
        total_obligaciones = int(k.get("total_obligaciones") or 0)
        abiertas = int(k.get("abiertas") or 0)
        fuera_sla = int(k.get("fuera_sla_abiertas") or 0)

    except Exception:
        # Fallback: si no existe la vista todavía, cuenta directo (menos escalable)
        try:
            r_sla = (
                sb.table("obligaciones")
                .select("id", count="exact")
                .eq("empresa_id", empresa_id)
                .eq("incumple_sla", True)
                .execute()
            )
            fuera_sla = r_sla.count or 0
        except Exception:
            fuera_sla = 0

    # --- KPIs (contratos + obligaciones) ---
    stats = {
        "total": len(todos),
        "proximos": len(vencen_30),
        "vencidos": len(vencidos_list),
        "sin_fecha": len(sin_fecha_list),

        # nuevo KPI que ya estás mostrando
        "fuera_sla": fuera_sla,

        # opcionales por si luego los quieres mostrar
        "obligaciones_total": total_obligaciones,
        "obligaciones_abiertas": abiertas,
    }

    ultimos = todos[:10]

    # --- Datos gráfico ---
    from collections import Counter
    grafico_meses = []

    for it in items:
        fecha = it.get("fecha_fin")
        if not fecha:
            continue
        try:
            fin = datetime.fromisoformat(str(fecha)).date()
            grafico_meses.append(fin.strftime("%Y-%m"))
        except:
            continue

    conteo = Counter(grafico_meses)
    grafico_labels = sorted(conteo.keys())
    grafico_values = [conteo[m] for m in grafico_labels]

    # --- Miembros (admin) ---
    miembros = []
    if rol == "admin" and supabase_service is not None:
        try:
            r = (
                supabase_service.table("usuarios_app")
                .select("username,rol,email_alertas,creado_en")
                .eq("empresa_id", empresa_id)
                .order("creado_en", desc=False)
                .execute()
            )
            miembros = r.data or []
        except:
            miembros = []

    # --- Return final ---
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "rol": rol,
        "mensaje": mensaje,
        "flash_msg": flash_msg,
        "hoy": hoy_str,

        "stats": stats,
        "todos": todos,
        "ultimos": ultimos,
        "vencen_30": vencen_30,
        "vencen_7": vencen_7,
        "vencidos_list": vencidos_list,
        "sin_fecha_list": sin_fecha_list,
        "miembros": miembros,
        "grafico_labels": grafico_labels,
        "grafico_values": grafico_values,
        "tipo_actual": tipo,
        "actividad": actividad
    })


@app.get("/actividad")
def actividad_page(request: Request, page: int = 1):

    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)

    PAGE_SIZE = 25
    offset = (page - 1) * PAGE_SIZE

    actividad = []

    try:
        rlog = (
            sb.table("audit_log")
            .select(
                "created_at,actor_username,action,entity_type,entity_id,metadata",
                count="exact"
            )
            .eq("empresa_id", empresa_id)
            .order("created_at", desc=True)
            .range(offset, offset + PAGE_SIZE - 1)
            .execute()
        )

        actividad = rlog.data or []
        total_registros = rlog.count or 0

    except Exception:
        actividad = []
        total_registros = 0


    return templates.TemplateResponse("actividad.html", {
        "request": request,
        "actividad": actividad,
        "page": page,
        "total_registros": total_registros
    })


# -----------------------------
# Subida PDF -> Supabase (Storage + DB)
# -----------------------------
@app.post("/subir_pdf/")
async def subir_pdf(request: Request, file: UploadFile = File(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    try:
        logger.info("Subida PDF iniciada user=%s file=%s", user, getattr(file, "filename", ""))

        # Validación: solo PDF
        ct = (file.content_type or "").lower()
        fname = (file.filename or "").strip()
        if "pdf" not in ct and not fname.lower().endswith(".pdf"):
            return RedirectResponse(url="/?ok=0&err=" + quote("Solo se permiten archivos PDF"), status_code=303)

        # Empresa
        empresa_id = get_empresa_id(user)
        if not empresa_id:
            return RedirectResponse(url="/?ok=0&err=" + quote("No tienes empresa asignada"), status_code=303)

        auth_user_id = get_auth_user_id_from_session(request)
        if not auth_user_id:
            return RedirectResponse(url="/?ok=0&err=" + quote("Sesión inválida (sin auth_user_id)"), status_code=303)

        erow = obtener_empresa_db(empresa_id) or {}
        empresa_nombre = erow.get("nombre", "MiEmpresa")

        # Evitar duplicado (CON RLS)
        try:
            res_dup = (
                sb.table("contratos")
                .select("archivo_pdf")
                .eq("empresa_id", empresa_id)
                .eq("archivo_pdf", fname)
                .limit(1)
                .execute()
            )
            if res_dup.data:
                return RedirectResponse(
                    url="/?ok=0&err=" + quote("Ya existe un contrato con ese nombre"),
                    status_code=303
                )
        except Exception as e:
            return RedirectResponse(url="/?ok=0&err=" + quote(f"Error comprobando duplicado: {str(e)[:120]}"), status_code=303)

        # Slugs para Storage path
        empresa_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", empresa_nombre).strip("_")
        user_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", user).strip("_")

        # Leer bytes
        pdf_bytes = await file.read()
        if not pdf_bytes:
            return RedirectResponse(url="/?ok=0&err=" + quote("Archivo vacío"), status_code=303)

        if len(pdf_bytes) > MAX_PDF_SIZE:
            return RedirectResponse(url="/?ok=0&err=" + quote("El archivo supera el límite de 20MB"), status_code=303)

        # Ruta en Storage
        storage_path = f"{empresa_id}/{auth_user_id}/{fname}"

        # Subir a Supabase Storage
        # (Esto no pasa por RLS como las tablas; lo dejamos tal cual para no romper)
        try:
            storage_client.storage.from_(BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={"content-type": file.content_type or "application/pdf"}
            )
        except Exception:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            storage_path = f"{empresa_slug}/{user_slug}/{ts}_{fname}"
            storage_client.storage.from_(BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={"content-type": file.content_type or "application/pdf"}
            )

        # Extraer texto + datos
        texto = extraer_texto_pdf_bytes(pdf_bytes)
        fecha_fin = extraer_fecha_fin(texto)
        tipo_contrato = clasificar_contrato(texto)

        # Insert en Postgres (CON RLS)
        sb.table("contratos").insert({
            "empresa_id": empresa_id,
            "owner_auth_id": auth_user_id,
            "owner": user,  # lo dejo para mostrar en UI/soporte (opcional)
            "archivo_pdf": fname,
            "storage_path": storage_path,
            "fecha_fin": fecha_fin,
            "tipo": tipo_contrato,
            "creado_en": utc_now_iso()
        }).execute()

        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="upload",
            entity_type="contratos",
            entity_id=fname,  # o puedes usar storage_path si prefieres
            metadata={
                "archivo_pdf": fname,
                "storage_path": storage_path,
                "tipo": tipo_contrato,
                "fecha_fin": fecha_fin
            },
            request=request
        )


        logger.info("Subida PDF OK user=%s storage_path=%s", user, storage_path)
        return RedirectResponse(url="/?ok=1", status_code=303)

    except Exception as e:
        logger.exception("Error en subir_pdf")
        return RedirectResponse(url="/?ok=0&err=" + quote(str(e)[:160]), status_code=303)


@app.get("/descargar/")
def descargar_pdf(request: Request, path: str):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    # Necesitamos supabase (service) para firmar URL de Storage
    if supabase is None:
        return RedirectResponse(url="/?ok=0&err=" + quote("Supabase no disponible"), status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/?ok=0&err=" + quote("No tienes empresa asignada"), status_code=303)

    # ✅ Seguridad con RLS: esta query solo devuelve filas permitidas por las policies
    try:
        res = (
            sb.table("contratos")
            .select("storage_path")
            .eq("empresa_id", empresa_id)
            .eq("storage_path", path)
            .limit(1)
            .execute()
        )
        if not res.data:
            return RedirectResponse(url="/?ok=0&err=" + quote("No autorizado"), status_code=303)

    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(str(e)[:120]), status_code=303)

    # ✅ Trazabilidad: registrar descarga (solo si está autorizado por RLS)
    log_event(
        sb=sb,
        empresa_id=empresa_id,
        action="download",
        entity_type="contratos",
        entity_id=path,
        metadata={"storage_path": path},
        request=request
    )

    # Generar URL firmada (10 minutos)
    try:
        signed = supabase.storage.from_(BUCKET).create_signed_url(path, 60 * 10)
        url = signed.get("signedURL") if isinstance(signed, dict) else None
        if not url:
            return RedirectResponse(url="/?ok=0&err=" + quote("No se pudo generar link"), status_code=303)
        return RedirectResponse(url=url, status_code=302)

    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(str(e)[:160]), status_code=303)


@app.post("/admin/borrar_contrato")
def admin_borrar_contrato(request: Request, contrato_id: int = Form(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if get_rol(user) != "admin":
        return RedirectResponse(url="/?ok=0&err=" + quote("Solo admin"), status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/?ok=0&err=" + quote("Admin sin empresa"), status_code=303)

    # 1) Leer contrato (RLS)
    try:
        res = (
            sb.table("contratos")
            .select("*")
            .eq("id", contrato_id)
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        if not row:
            return RedirectResponse(url="/?ok=0&err=" + quote("No existe o no autorizado"), status_code=303)
    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(f"Error leyendo contrato: {str(e)[:120]}"), status_code=303)

    # 2) Insertar en papelera y 3) borrar de contratos
    try:

        sb.table("contratos_papelera").insert(row).execute()

        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="delete",
            entity_type="contratos",
            entity_id=str(contrato_id),
            metadata={"storage_path": row.get("storage_path"), "archivo_pdf": row.get("archivo_pdf")},
            request=request
        )


    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(f"Error moviendo a papelera: {str(e)[:120]}"), status_code=303)

    try:
        sb.table("contratos").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
    except Exception as e:
        # rollback: si no pudo borrar en contratos, quitamos el duplicado de papelera
        try:
            sb.table("contratos_papelera").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
        except:
            pass
        return RedirectResponse(url="/?ok=0&err=" + quote(f"Error borrando contrato: {str(e)[:120]}"), status_code=303)

    return RedirectResponse(url="/?ok=1", status_code=303)


@app.get("/admin/papelera")
def admin_papelera(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if get_rol(user) != "admin":
        return RedirectResponse(url="/", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/?ok=0&err=" + quote("Admin sin empresa"), status_code=303)

    res = (
        sb.table("contratos_papelera")
        .select("id,archivo_pdf,fecha_fin,tipo,owner,storage_path,creado_en")
        .eq("empresa_id", empresa_id)
        .order("creado_en", desc=True)
        .limit(300)
        .execute()
    )

    papelera = res.data or []
    return templates.TemplateResponse("papelera.html", {
        "request": request,
        "user": user,
        "rol": "admin",
        "papelera": papelera
    })


@app.post("/admin/restaurar_contrato")
def admin_restaurar_contrato(request: Request, contrato_id: int = Form(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if get_rol(user) != "admin":
        return RedirectResponse(url="/", status_code=303)

    if supabase_service is None:
        return RedirectResponse(url="/admin/papelera?err=" + quote("Supabase service no disponible"), status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/admin/papelera?err=" + quote("Admin sin empresa"), status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    # 1) leer de papelera (service role para evitar RLS)
    try:
        res = (
            supabase_service.table("contratos_papelera")
            .select("*")
            .eq("id", contrato_id)
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        if not row:
            return RedirectResponse(url="/admin/papelera", status_code=303)
    except Exception as e:
        return RedirectResponse(url="/admin/papelera?err=" + quote(f"Error leyendo papelera: {str(e)[:160]}"), status_code=303)

    storage_path = row.get("storage_path")

    # 2) si YA existe en contratos por storage_path, limpia papelera y listo
    try:
        if storage_path:
            ex = (
                supabase_service.table("contratos")
                .select("id")
                .eq("empresa_id", empresa_id)
                .eq("storage_path", storage_path)
                .limit(1)
                .execute()
            )
            if ex.data:
                supabase_service.table("contratos_papelera").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
                # log (como purge de papelera por duplicado)
                log_event(
                    sb=sb,
                    empresa_id=empresa_id,
                    action="purge",
                    entity_type="contratos_papelera",
                    entity_id=str(contrato_id),
                    metadata={"storage_path": storage_path, "reason": "already_restored_clean"},
                    request=request
                )
                return RedirectResponse(url="/?ok=1", status_code=303)
    except Exception:
        pass

    # 3) insertar en contratos SIN id
    row_to_insert = dict(row)
    row_to_insert.pop("id", None)

    try:
        supabase_service.table("contratos").insert(row_to_insert).execute()

        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="restore",
            entity_type="contratos",
            entity_id=str(contrato_id),
            metadata={"storage_path": storage_path},
            request=request
        )

    except Exception as e:
        msg = str(e)

        # Si es UNIQUE (23505), significa "ya existe algo equivalente"
        if "23505" in msg or "duplicate key value violates unique constraint" in msg.lower():
            try:
                supabase_service.table("contratos_papelera").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
                log_event(
                    sb=sb,
                    empresa_id=empresa_id,
                    action="purge",
                    entity_type="contratos_papelera",
                    entity_id=str(contrato_id),
                    metadata={"storage_path": storage_path, "reason": "duplicate_restore_clean"},
                    request=request
                )
                return RedirectResponse(url="/?ok=1", status_code=303)
            except Exception:
                return RedirectResponse(url="/admin/papelera?err=" + quote(f"Duplicado detectado pero no se pudo limpiar: {msg[:180]}"), status_code=303)

        return RedirectResponse(url="/admin/papelera?err=" + quote(f"Error restaurando: {msg[:180]}"), status_code=303)

    # 4) borrar de papelera (service role)
    try:
        supabase_service.table("contratos_papelera").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
    except Exception as e:
        return RedirectResponse(url="/admin/papelera?err=" + quote(f"Restaurado, pero no se pudo limpiar papelera: {str(e)[:160]}"), status_code=303)

    return RedirectResponse(url="/?ok=1", status_code=303)


@app.post("/admin/borrar_definitivo")
def admin_borrar_definitivo(request: Request, contrato_id: int = Form(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if get_rol(user) != "admin":
        return RedirectResponse(url="/", status_code=303)

    if supabase_service is None:
        return RedirectResponse(url="/admin/papelera?err=" + quote("Supabase service no disponible"), status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/admin/papelera?err=" + quote("Admin sin empresa"), status_code=303)

    # 1) leer storage_path desde papelera
    try:
        res = (
            supabase_service.table("contratos_papelera")
            .select("storage_path")
            .eq("id", contrato_id)
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        if not row:
            return RedirectResponse(url="/admin/papelera", status_code=303)
        storage_path = row.get("storage_path")
    except Exception as e:
        return RedirectResponse(url="/admin/papelera?err=" + quote(f"Error leyendo papelera: {str(e)[:160]}"), status_code=303)

    # 2) borrar fila de papelera (service role, sin RLS)
    try:
        supabase_service.table("contratos_papelera").delete().eq("id", contrato_id).eq("empresa_id", empresa_id).execute()
    except Exception as e:
        return RedirectResponse(url="/admin/papelera?err=" + quote(f"No se pudo borrar de papelera: {str(e)[:160]}"), status_code=303)

    # 3) borrar archivo de storage (si existe)
    if storage_path:
        try:
            storage_client.storage.from_(BUCKET).remove([storage_path])
        except Exception as e:
            return RedirectResponse(url="/admin/papelera?err=" + quote(f"Borrado en DB, pero fallo borrando archivo: {str(e)[:160]}"), status_code=303)

        # ✅ AUDIT LOG: purge
        sb = supabase_user_client(request)
        if sb is not None:
            log_event(
                sb=sb,
                empresa_id=empresa_id,
                action="purge",
                entity_type="contratos_papelera",
                entity_id=str(contrato_id),
                metadata={"storage_path": storage_path},
                request=request
            )

    return RedirectResponse(url="/admin/papelera?ok=1", status_code=303)



# -----------------------------
# Consultas
# -----------------------------
@app.get("/vencen_en/")
def vencen_en(request: Request, dias: int = 30):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return {"ok": False, "error": "Sesión expirada. Vuelve a iniciar sesión.", "resultados": []}

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return {"ok": False, "error": "No tienes empresa asignada", "resultados": []}

    # RLS filtra automáticamente (admin ve empresa, miembro ve lo suyo)
    alertas = obtener_alertas_supabase(sb, empresa_id=empresa_id, dias=dias)

    resultados = [{
        "archivo_pdf": a.get("archivo_pdf"),
        "tipo": a.get("tipo", "otro"),
        "vence_el": a.get("vence_el"),
        "dias_restantes": a.get("dias_restantes")
    } for a in alertas]

    return {
        "ok": True,
        "hoy": datetime.now().date().isoformat(),
        "dias": dias,
        "resultados": resultados
    }


@app.get("/alertas_vencimiento/")
def alertas_vencimiento(request: Request, dias: int = 30):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return {"ok": False, "error": "Sesión expirada. Vuelve a iniciar sesión.", "alertas": []}

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return {"ok": False, "error": "No tienes empresa asignada", "alertas": []}

    # RLS filtra automáticamente
    alertas = obtener_alertas_supabase(sb, empresa_id=empresa_id, dias=dias)

    return {
        "ok": True,
        "dias": dias,
        "alertas": alertas
    }


@app.post("/preguntar_contratos/")
async def preguntar_contratos(request: Request, pregunta: str = Form(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    rol = get_rol(user)
    empresa_id = get_empresa_id(user)

    sb = supabase_user_client(request)
    if sb is None:
        return RedirectResponse(url="/login", status_code=303)

    auth_user_id = get_auth_user_id_from_session(request)

    if not empresa_id:
        return RedirectResponse(url="/config", status_code=303)

    # =============================
    # 1) Interpretar la pregunta
    # =============================
    pregunta_l = (pregunta or "").lower().strip()
    hoy = datetime.now().date()
    hoy_iso = hoy.isoformat()

    ventana = 10  # rango ±10 días

    solo_vencidos = "vencidos" in pregunta_l
    solo_sin_fecha = "sin fecha" in pregunta_l or "sin vencimiento" in pregunta_l

    # -----------------------------
    # PARSER DÍAS / MESES
    # -----------------------------
    dias = None

    # 1) "X días"
    m_dias = re.search(r"\b(\d{1,4})\s*d[ií]as?\b", pregunta_l)
    if m_dias:
        dias = int(m_dias.group(1))

    # 2) "en X" (si no habla de meses)
    if dias is None and "mes" not in pregunta_l:
        m_en = re.search(r"\ben\s+(\d{1,4})\b", pregunta_l)
        if m_en:
            dias = int(m_en.group(1))

    # 3) Meses
    meses = None
    m_mes = re.search(r"\b(\d{1,3})\s*mes(?:es)?\b", pregunta_l)
    if m_mes:
        meses = int(m_mes.group(1))

    dias_extra = 0
    m_extra = re.search(r"y\s+(\d{1,4})\s*d[ií]as?\b", pregunta_l)
    if m_extra:
        dias_extra = int(m_extra.group(1))

    if meses is not None:
        dias = (meses * 30) + dias_extra

    # 4) Número suelto
    if dias is None and "mes" not in pregunta_l:
        m_num = re.search(r"\b(\d{1,4})\b", pregunta_l)
        if m_num and ("venc" in pregunta_l or "dias" in pregunta_l or "día" in pregunta_l):
            dias = int(m_num.group(1))

    # Default
    if dias is None and "venc" in pregunta_l:
        dias = 30

    # -----------------------------
    # FILTRO TIPO
    # -----------------------------
    tipos_validos = ["alquiler", "seguro", "servicios", "laboral", "préstamo", "prestamo", "otro"]
    tipo_filtro = None
    for t in tipos_validos:
        if t in pregunta_l:
            tipo_filtro = "préstamo" if t == "prestamo" else t
            break

    # =============================
    # 2) QUERY SUPABASE
    # =============================
    query = (
        sb.table("contratos")
        .select("id,archivo_pdf,fecha_fin,tipo,owner,storage_path,creado_en")
        .eq("empresa_id", empresa_id)
    )

    if rol != "admin":
        if not auth_user_id:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)
        query = query.eq("owner_auth_id", auth_user_id)

    if tipo_filtro:
        query = query.eq("tipo", tipo_filtro)

    if solo_sin_fecha:
        query = query.is_("fecha_fin", "null").order("creado_en", desc=True)

    elif solo_vencidos:
        query = query.lt("fecha_fin", hoy_iso).order("fecha_fin", desc=True)

    elif dias is not None:
        objetivo = hoy + timedelta(days=dias)
        inicio = (objetivo - timedelta(days=ventana)).isoformat()
        fin = (objetivo + timedelta(days=ventana)).isoformat()

        query = (
            query
            .gte("fecha_fin", inicio)
            .lte("fecha_fin", fin)
            .order("fecha_fin", desc=False)
        )
    else:
        query = query.order("creado_en", desc=True)

    query = query.limit(300)

    try:
        items = query.execute().data or []
    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            return RedirectResponse(url="/login", status_code=303)

        return templates.TemplateResponse("respuesta.html", {
            "request": request,
            "pregunta": pregunta,
            "resumen": f"❌ Error consultando Supabase: {str(e)[:180]}",
            "resultados": [],
            "rol": rol,
        })

    # =============================
    # 3) FORMATEAR RESULTADOS
    # =============================
    resultados = []

    for it in items:
        fecha_raw = it.get("fecha_fin")
        archivo = it.get("archivo_pdf") or ""
        tipo = it.get("tipo") or "otro"
        owner = it.get("owner") or ""
        storage_path = it.get("storage_path") or ""
        cid = it.get("id")

        if not fecha_raw:
            resultados.append({
                "id": cid,
                "archivo": archivo,
                "tipo": tipo,
                "fecha": None,
                "estado": "Sin fecha",
                "dias": None,
                "owner": owner,
                "storage_path": storage_path,
            })
            continue

        try:
            fecha_str = str(fecha_raw)[:10]
            fin_date = datetime.fromisoformat(fecha_str).date()
        except:
            continue

        dias_restantes = (fin_date - hoy).days
        estado = "Vencido" if fin_date < hoy else "Próximo"

        resultados.append({
            "id": cid,
            "archivo": archivo,
            "tipo": tipo,
            "fecha": fin_date.isoformat(),
            "estado": estado,
            "dias": dias_restantes,
            "owner": owner,
            "storage_path": storage_path,
        })

    resultados.sort(key=lambda r: (r["dias"] is None, r["dias"] or 999999))

    total = len(resultados)
    resumen = (
        f"Se encontraron {total} contratos alrededor de {dias} días (±{ventana})."
        if dias is not None else
        f"Se encontraron {total} contratos."
    )

    return templates.TemplateResponse("respuesta.html", {
        "request": request,
        "pregunta": pregunta,
        "resultados": resultados,
        "resumen": resumen,
        "rol": rol,
    })


# -----------------------------
# Config (email por usuario)
# -----------------------------
@app.get("/config")
def config_get(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase is None:
        return templates.TemplateResponse("config.html", {
            "request": request,
            "empresa": "",
            "codigo": "",
            "email": "",
            "rol": "",
            "ok": False,
            "error": "Supabase no disponible"
        })

    # Leer usuario
    u = obtener_usuario_db(user) or {}
    rol = (u.get("rol") or "admin").strip().lower()
    email = (u.get("email_alertas") or "")

    # Leer empresa desde empresa_id
    empresa_id = u.get("empresa_id")
    empresa = ""
    codigo = ""

    if empresa_id:
        erow = obtener_empresa_db(str(empresa_id)) or {}
        empresa = erow.get("nombre", "") or ""
        codigo = erow.get("codigo", "") or ""

        # Si es admin y hay empresa pero no hay código, generarlo en empresas
        if rol == "admin" and empresa and not codigo:
            codigo = generar_codigo_empresa()
            supabase.table("empresas").update({"codigo": codigo}).eq("id", str(empresa_id)).execute()

    return templates.TemplateResponse("config.html", {
        "request": request,
        "empresa": empresa,
        "codigo": codigo,
        "email": email,
        "rol": rol,
        "ok": False,
        "error": None
    })


@app.post("/config")
def config_post(request: Request, email: str = Form(""), empresa: str = Form("")):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase is None:
        return templates.TemplateResponse("config.html", {
            "request": request,
            "empresa": "",
            "codigo": "",
            "email": email or "",
            "rol": "",
            "ok": False,
            "error": "Supabase no disponible"
        })

    # Leer usuario UNA vez
    u = obtener_usuario_db(user) or {}
    rol = (u.get("rol") or "admin").strip().lower()

    # Guardar email (siempre permitido)
    set_email_alertas(user, email)

    empresa_in = (empresa or "").strip()

    if empresa_in:
        if rol != "admin":
            u2 = obtener_usuario_db(user) or {}
            empresa_id_2 = u2.get("empresa_id")
            erow2 = obtener_empresa_db(empresa_id_2) or {}

            return templates.TemplateResponse("config.html", {
                "request": request,
                "empresa": erow2.get("nombre", ""),
                "codigo": erow2.get("codigo", ""),
                "email": u2.get("email_alertas") or (email or ""),
                "rol": rol,
                "ok": False,
                "error": "Solo un admin puede cambiar la empresa."
            })

        # --- SOLO ADMIN LLEGA AQUÍ ---
        empresa_id = get_empresa_id(user)

        if not empresa_id:
            res_new = supabase.table("empresas").insert({"nombre": empresa_in}).execute()
            new_row = (res_new.data or [None])[0]

            if not new_row:
                return templates.TemplateResponse("config.html", {
                    "request": request,
                    "empresa": "",
                    "codigo": "",
                    "email": email or "",
                    "rol": rol,
                    "ok": False,
                    "error": "No se pudo crear la empresa"
                })

            set_empresa_id(user, new_row["id"])
            empresa_id = new_row["id"]  # ✅ importante para leer en esta misma request

        else:
            supabase.table("empresas").update({"nombre": empresa_in}).eq("id", empresa_id).execute()

    # BLOQUE PARA LEER EMPRESA (desde tabla empresas)
    empresa_id = get_empresa_id(user)
    erow = obtener_empresa_db(empresa_id) or {}
    empresa_final = erow.get("nombre", "")
    codigo_final = erow.get("codigo", "")

    # Leer email actualizado desde DB
    u3 = obtener_usuario_db(user) or {}
    email_final = (u3.get("email_alertas") or "")

    # Si falta código (solo admin), guardarlo en empresas
    if rol == "admin" and empresa_id and empresa_final and not codigo_final:
        codigo_final = generar_codigo_empresa()
        supabase.table("empresas").update({"codigo": codigo_final}).eq("id", empresa_id).execute()

    sb = supabase_user_client(request)
    if sb is not None and empresa_id:
        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="config_update",
            entity_type="config",
            entity_id=user,
            metadata={"email": email_final, "empresa": empresa_final},
            request=request
        )

    return templates.TemplateResponse("config.html", {
        "request": request,
        "empresa": empresa_final,
        "codigo": codigo_final,
        "email": email_final,
        "rol": rol,
        "ok": True,
        "error": None
    })


class ResendError(Exception):
    def __init__(self, status_code: int, body: str):
        self.status_code = int(status_code)
        self.body = body or ""
        super().__init__(f"Resend error {self.status_code}: {self.body[:300]}")


# -----------------------------
# Email
# -----------------------------
def enviar_email(destino: str, asunto: str, mensaje: str) -> str:
    """
    Envío de email vía Resend.
    Devuelve provider_id (message id) si todo va bien.
    Lanza excepción si falla.
    """

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    mail_from = os.environ.get("MAIL_FROM", "").strip()

    if not api_key or not mail_from:
        raise RuntimeError("Faltan RESEND_API_KEY o MAIL_FROM en variables de entorno.")

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "from": mail_from,
            "to": [destino],
            "subject": asunto,
            "text": mensaje,
        },
        timeout=30,
    )

    if resp.status_code >= 300:
        raise ResendError(resp.status_code, resp.text)

    data = resp.json()

    # Resend devuelve {"id": "..."}
    provider_id = data.get("id")
    if not provider_id:
        raise RuntimeError("Resend no devolvió message id")

    return provider_id


@app.get("/enviar_alertas/")
def enviar_alertas(request: Request, dias: int = 30):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        return {"ok": False, "error": "Sesión expirada. Vuelve a iniciar sesión.", "enviados": []}

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return {"ok": False, "error": "No tienes empresa asignada", "enviados": []}

    destino = get_email_alertas(user)
    if not destino:
        return {"ok": False, "error": "No tienes email configurado en /config", "enviados": []}

    alertas = obtener_alertas_supabase(sb, empresa_id=empresa_id, dias=dias)

    if not alertas:
        return {"ok": True, "mensaje": "No hay contratos por vencer", "enviados": []}

    asunto = f"Alertas de contratos (<= {dias} días)"
    cuerpo = "Contratos próximos a vencer:\n\n" + "\n".join(
        [f"- {a['archivo_pdf']} ({a.get('tipo','otro')}) vence el {a['vence_el']} (quedan {a['dias_restantes']} días)"
         for a in alertas]
    )

    try:
        enviar_email(destino, asunto, cuerpo)
    except Exception as e:
        return {"ok": False, "error": f"Fallo enviando email: {str(e)[:180]}", "enviados": []}

    return {"ok": True, "enviados": [{"owner": user, "destino": destino, "num_alertas": len(alertas)}]}




@app.post("/jobs/enviar_alertas_diarias")
def job_enviar_alertas_diarias(x_cron_secret: str = Header(None)):
    """
    Cron diario:
    - Busca contratos que vencen en 30 días (fecha_fin)
    - Envía email si hay destinatarios
    - Registra alert_sent en audit_log (evento de negocio)
    - Registra ejecución en job_runs (operacional)
    """

    # -------------------------
    # Seguridad del cron
    # -------------------------
    if CRON_SECRET and x_cron_secret != CRON_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="Service role no configurado")

    # -------------------------
    # Registrar inicio del job
    # -------------------------
    job_name = "enviar_alertas_diarias"
    started_at = datetime.utcnow()

    job_run_id = job_run_start(job_name, metadata={
        "dias": 30,
        "ts": started_at.isoformat()
    })

    try:
        hoy = utc_now().date()
        fecha_objetivo = hoy + timedelta(days=30)

        empresas_total = 0
        empresas_envio_ok = 0
        empresas_con_contratos = 0
        total_contratos_encontrados = 0

        # Obtener empresas (solo ids)
        empresas_resp = supabase_service.table("empresas").select("id").execute()
        empresas = empresas_resp.data or []
        empresas_total = len(empresas)

        for emp in empresas:
            empresa_id = emp["id"]

            # Buscar contratos que vencen en 30 días (en tu schema: fecha_fin es DATE)
            contratos_resp = (
                supabase_service
                .table("contratos")
                .select("storage_path, archivo_pdf, fecha_fin, empresa_id")
                .eq("empresa_id", empresa_id)
                .eq("fecha_fin", str(fecha_objetivo))   # PostgREST con DATE: enviar "YYYY-MM-DD"
                .execute()
            )

            contratos = contratos_resp.data or []
            if not contratos:
                continue

            empresas_con_contratos += 1
            total_contratos_encontrados += len(contratos)

            # Obtener emails configurados
            admins = (
                supabase_service.table("usuarios_app")
                .select("email_alertas")
                .eq("empresa_id", empresa_id)
                .eq("rol", "admin")
                .execute()
            )
            destinatarios = [
                (a.get("email_alertas") or "").strip()
                for a in (admins.data or [])
                if (a.get("email_alertas") or "").strip()
            ]
            if not destinatarios:
                  continue

            # Nombre visible del contrato: archivo_pdf (si no hay, usamos storage_path)
            def label(c: dict) -> str:
                return c.get("archivo_pdf") or c.get("storage_path") or "(sin nombre)"

            # Construir cuerpo del email
            lista_html = "".join([
                f"<li>{label(c)} — vence el {c['fecha_fin']}</li>"
                for c in contratos
            ])

            asunto = "Contratos que vencen en 30 días"
            html = f"""
                <h3>Contratos por vencer</h3>
                <p>Los siguientes contratos vencen en 30 días:</p>
                <ul>
                    {lista_html}
                </ul>
            """

            try:
                # Enviar email (texto) a cada destinatario usando tu enviar_email()
                cuerpo = "Contratos que vencen en 30 días:\n\n" + "\n".join(
                    [f"- {label(c)} — vence el {c['fecha_fin']}" for c in contratos]
                )

                for destino in destinatarios:
                    enviar_email(destino, asunto, cuerpo)

                empresas_envio_ok += 1

                # Evento de negocio: alert_sent
                supabase_service.table("audit_log").insert({
                    "empresa_id": empresa_id,
                    "actor_username": "system",
                    "actor_auth_id": None,
                    "action": "alert_sent",
                    "entity_type": "contratos",
                    "entity_id": None,
                    "metadata": {
                        "dias": 30,
                        "fecha_objetivo": str(fecha_objetivo),
                        "destinatarios": destinatarios,
                        "contratos": [
                            {
                                "storage_path": c.get("storage_path"),
                                "archivo_pdf": c.get("archivo_pdf"),
                                "fecha_fin": str(c.get("fecha_fin"))
                            }
                            for c in contratos
                        ]
                    }
                }).execute()

            except Exception as mail_error:
                logger.error(f"Error enviando email empresa {empresa_id}: {mail_error}")

        # -------------------------
        # Finalizar job (SUCCESS)
        # -------------------------
        job_run_finish(
            job_run_id=job_run_id,
            status="success",
            metadata={
                "dias": 30,
                "fecha_objetivo": str(fecha_objetivo),
                "empresas_total": empresas_total,
                "empresas_envio_ok": empresas_envio_ok,
                "empresas_con_contratos": empresas_con_contratos,
                "total_contratos_encontrados": total_contratos_encontrados
            },
            started_at=started_at
        )

        return {
            "ok": True,
            "fecha_objetivo": str(fecha_objetivo),
            "empresas_total": empresas_total,
            "empresas_envio_ok": empresas_envio_ok,
            "empresas_con_contratos": empresas_con_contratos,
            "total_contratos_encontrados": total_contratos_encontrados
        }

    except Exception as ex:
        job_run_finish(
            job_run_id=job_run_id,
            status="error",
            metadata={"error": str(ex)[:240]},
            started_at=started_at
        )
        raise


@app.post("/jobs/enviar_alertas_obligaciones_30d")
def job_enviar_alertas_obligaciones_30d(x_cron_secret: str = Header(None)):
    """
    Job diario (obligaciones) — modo OUTBOX serio:
    - Lee obligaciones dentro de un lookahead.
    - Aplica políticas (recordatorios_dias).
    - Inserta en outbox (tabla notificaciones) con dedupe_key estable.
    - NO envía emails aquí. El envío lo hace procesar_notificaciones_pendientes().
    """

    # Seguridad cron
    if CRON_SECRET and x_cron_secret != CRON_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="Service role no configurado")

    job_name = "enviar_alertas_obligaciones"
    started_at_dt = datetime.utcnow()

    canal = "email"
    LOOKAHEAD_DIAS = 180  # cubre múltiples recordatorios (60/30/15, 45/15/7, etc.)

    job_run_id = job_run_start(job_name, metadata={
        "lookahead_dias": LOOKAHEAD_DIAS,
        "canal": canal
    })

    # contadores (mantenemos nombres para no romper dashboards/monitoring)
    total_encontradas = 0
    candidatos_por_politica = 0
    enviados = 0                 # ahora significa "generadas en outbox"
    saltados_por_antispam = 0    # ahora significa "dedupe hit"
    sin_responsable = 0
    sin_email = 0
    errores_envio = 0            # ahora significa "errores insertando outbox"

    hoy = utc_now().date()
    hasta = hoy + timedelta(days=LOOKAHEAD_DIAS)

    try:
        # 1) Traer obligaciones del rango (no hardcode a 30)
        resp = (
            supabase_service
            .table("obligaciones")
            .select("id,empresa_id,titulo,tipo,fecha_limite,estado,responsable_auth_id")
            .gte("fecha_limite", str(hoy))
            .lte("fecha_limite", str(hasta))
            .execute()
        )

        obligaciones = resp.data or []
        total_encontradas = len(obligaciones)

        for ob in obligaciones:
            obligacion_id = ob.get("id")
            empresa_id = ob.get("empresa_id")
            titulo = (ob.get("titulo") or "(sin título)").strip()
            tipo = ob.get("tipo")
            responsable_auth_id = ob.get("responsable_auth_id")

            if not responsable_auth_id:
                sin_responsable += 1
                continue

            # 2) Calcular días restantes
            try:
                fecha_limite = datetime.fromisoformat(str(ob.get("fecha_limite"))[:10]).date()
            except Exception:
                continue

            dias_restantes = (fecha_limite - hoy).days
            if dias_restantes < 0:
                continue

            # 3) Políticas por empresa y por tipo
            pol_emp = get_empresa_politica(str(empresa_id))
            pol_tipo = get_obligacion_politica(str(empresa_id), tipo)

            recordatorios = pol_tipo.get("recordatorios_dias") or [30]
            # normalizar a ints
            recordatorios = [int(x) for x in recordatorios if str(x).strip().lstrip("-").isdigit()]

            if dias_restantes not in set(recordatorios):
                continue

            candidatos_por_politica += 1

            antispam_horas = int(pol_emp.get("antispam_horas") or 24)

            # Tipo de aviso: "45d", "30d", "7d"...
            tipo_aviso = f"{dias_restantes}d"

            # 4) Email del responsable
            u = (
                supabase_service
                .table("usuarios_app")
                .select("username,email_alertas,auth_user_id")
                .eq("auth_user_id", responsable_auth_id)
                .limit(1)
                .execute()
            )
            user_row = (u.data or [None])[0] or {}
            email_to = (user_row.get("email_alertas") or "").strip()

            if not email_to:
                sin_email += 1
                continue

            # 5) Insert OUTBOX (idempotente por dedupe_key estable)
            dedupe_key = f"{tipo_aviso}:{canal}:{obligacion_id}:{fecha_limite.isoformat()}"

            try:
                insertada = outbox_insert_notificacion(
                    sb=supabase_service,  # service_role ok (job)
                    empresa_id=str(empresa_id),
                    canal=canal,
                    destinatarios=[email_to],
                    tipo_aviso=tipo_aviso,
                    metadata={
                        "fecha_limite": fecha_limite.isoformat(),
                        "dias_restantes": dias_restantes,
                        "responsable_auth_id": responsable_auth_id,
                        "titulo": titulo,
                        "tipo": tipo,
                        "politica": {
                            "recordatorios_dias": recordatorios,
                            "antispam_horas": antispam_horas
                        }
                    },
                    dedupe_key=dedupe_key,
                    obligacion_id=str(obligacion_id),
                )

                if insertada:
                    enviados += 1
                else:
                    saltados_por_antispam += 1

            except Exception as e:
                errores_envio += 1
                logger.error(
                    "Error insertando outbox obligacion=%s empresa=%s: %s",
                    obligacion_id, empresa_id, str(e)[:200]
                )
                continue

        # FIN OK
        job_run_finish(
            job_run_id=job_run_id,
            status="success",
            metadata={
                "hoy": str(hoy),
                "hasta": str(hasta),
                "lookahead_dias": LOOKAHEAD_DIAS,
                "total_encontradas": total_encontradas,
                "candidatos_por_politica": candidatos_por_politica,
                "generadas_outbox": enviados,
                "dedupe_hits": saltados_por_antispam,
                "sin_responsable": sin_responsable,
                "sin_email": sin_email,
                "errores_outbox": errores_envio,
            },
            started_at=started_at_dt
        )

        return {
            "ok": True,
            "hoy": str(hoy),
            "hasta": str(hasta),
            "lookahead_dias": LOOKAHEAD_DIAS,
            "total_encontradas": total_encontradas,
            "candidatos_por_politica": candidatos_por_politica,
            "generadas_outbox": enviados,
            "dedupe_hits": saltados_por_antispam,
            "sin_responsable": sin_responsable,
            "sin_email": sin_email,
            "errores_outbox": errores_envio,
        }

    except Exception as ex:
        job_run_finish(
            job_run_id=job_run_id,
            status="error",
            metadata={"error": str(ex)[:240]},
            started_at=started_at_dt
        )
        raise HTTPException(status_code=500, detail=str(ex)[:200])


@app.post("/jobs/recalcular_sla_obligaciones")
def job_recalcular_sla_obligaciones(x_cron_secret: str = Header(None)):
    """
    Cron diario:
    - Recalcula incumple_sla en obligaciones según internal_deadline.
    - Si internal_deadline es NULL, intenta calcularlo desde obligacion_politicas (sla_dias_antes).
    - NO cambia estado.
    - Deja trazabilidad en job_runs.
    """
    # Seguridad
    if CRON_SECRET and x_cron_secret != CRON_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="Service role no configurado")

    job_name = "recalcular_sla_obligaciones"
    started_at_dt = datetime.utcnow()
    hoy = started_at_dt.date()

    job_run_id = job_run_start(job_name, metadata={"hoy": str(hoy)})

    actualizadas_true = 0
    actualizadas_false = 0
    internal_backfilled = 0
    total_con_fecha_limite = 0
    errores = 0

    try:
        # Traer obligaciones con fecha_limite (aunque internal_deadline sea NULL)
        resp = (
            supabase_service
            .table("obligaciones")
            .select("id,empresa_id,tipo,estado,fecha_limite,internal_deadline,incumple_sla")
            .not_.is_("fecha_limite", "null")
            .execute()
        )

        items = resp.data or []
        total_con_fecha_limite = len(items)

        for ob in items:
            oid = ob.get("id")
            empresa_id = ob.get("empresa_id")
            tipo = ob.get("tipo")
            estado = (ob.get("estado") or "").strip().lower()

            # 1) Si internal_deadline es NULL -> calcularlo desde política
            internal_raw = ob.get("internal_deadline")

            if not internal_raw:
                try:
                    pol = get_obligacion_politica(str(empresa_id), tipo)
                    sla_dias = pol.get("sla_dias_antes")

                    if sla_dias is not None:
                        sla_dias = int(sla_dias)

                        fl = datetime.fromisoformat(str(ob.get("fecha_limite"))[:10]).date()
                        internal_calc = (fl - timedelta(days=sla_dias)).isoformat()

                        supabase_service.table("obligaciones").update({
                            "internal_deadline": internal_calc,
                            "actualizado_en": utc_now_iso()
                        }).eq("id", oid).execute()

                        internal_raw = internal_calc
                        internal_backfilled += 1
                except Exception as e:
                    errores += 1
                    logger.warning("Backfill internal_deadline fallo obligacion=%s err=%s", oid, str(e)[:160])
                    internal_raw = None

            # Si sigue sin internal_deadline (porque no hay SLA en política), saltamos
            if not internal_raw:
                continue

            # 2) Calcular si incumple SLA
            try:
                internal_date = datetime.fromisoformat(str(internal_raw)[:10]).date()
            except Exception:
                errores += 1
                continue

            debe_incumplir = (hoy > internal_date) and (estado != "resuelta")

            # Evitar updates innecesarios
            if bool(ob.get("incumple_sla")) == bool(debe_incumplir):
                continue

            supabase_service.table("obligaciones").update({
                "incumple_sla": bool(debe_incumplir),
                "actualizado_en": utc_now_iso()
            }).eq("id", oid).execute()

            if debe_incumplir:
                actualizadas_true += 1
            else:
                actualizadas_false += 1

        job_run_finish(
            job_run_id=job_run_id,
            status="success",
            metadata={
                "hoy": str(hoy),
                "total_con_fecha_limite": total_con_fecha_limite,
                "internal_backfilled": internal_backfilled,
                "actualizadas_true": actualizadas_true,
                "actualizadas_false": actualizadas_false,
                "errores": errores
            },
            started_at=started_at_dt
        )

        return {
            "ok": True,
            "hoy": str(hoy),
            "total_con_fecha_limite": total_con_fecha_limite,
            "internal_backfilled": internal_backfilled,
            "actualizadas_true": actualizadas_true,
            "actualizadas_false": actualizadas_false,
            "errores": errores
        }

    except Exception as ex:
        job_run_finish(
            job_run_id=job_run_id,
            status="error",
            metadata={"error": str(ex)[:240]},
            started_at=started_at_dt
        )
        raise HTTPException(status_code=500, detail=str(ex)[:200])


@app.get("/debug_job_alertas")
def debug_job_alertas():
    if supabase_service is None:
        return {"ok": False, "error": "no supabase_service"}

    hoy = utc_now().date()
    limite = hoy + timedelta(days=30)

    empresas = supabase_service.table("empresas").select("id,nombre").execute().data or []
    out = {"empresas": len(empresas), "detalle": []}

    for emp in empresas[:20]:
        empresa_id = emp.get("id")

        admins = (
            supabase_service.table("usuarios_app")
            .select("username,rol,email_alertas,empresa_id")
            .eq("empresa_id", empresa_id)
            .eq("rol", "admin")
            .execute()
            .data
        ) or []

        destinos = [a.get("email_alertas", "").strip() for a in admins if (a.get("email_alertas") or "").strip()]

        contratos = (
            supabase_service.table("contratos")
            .select("id,archivo_pdf,fecha_fin")
            .eq("empresa_id", empresa_id)
            .gte("fecha_fin", hoy.isoformat())
            .lte("fecha_fin", limite.isoformat())
            .limit(10)
            .execute()
            .data
        ) or []

        out["detalle"].append({
            "empresa_id": empresa_id,
            "empresa_nombre": emp.get("nombre"),
            "admins_encontrados": len(admins),
            "destinos_no_vacios": len(destinos),
            "contratos_en_30": len(contratos),
            "ejemplo_fecha_fin": (contratos[0].get("fecha_fin") if contratos else None)
        })

    return out


@app.get("/jobs/process_outbox")
def jobs_process_outbox(
    request: Request,
    limite_empresas: int = 50,
    limite_por_empresa: int = 50,
    x_job_secret: str | None = Header(default=None),
):
    """
    Cron global: procesa pendientes de TODAS las empresas.
    Protegido por OUTBOX_JOB_SECRET.
    Registra ejecución en job_runs (schema real: job_name, status, started_at, finished_at, duration_s, metadata).
    """
    if supabase_service is None:
        raise HTTPException(status_code=500, detail="supabase_service no configurado")

    expected = os.getenv("OUTBOX_JOB_SECRET")
    if not expected:
        raise HTTPException(status_code=500, detail="OUTBOX_JOB_SECRET no configurado")

    if x_job_secret != expected:
        raise HTTPException(status_code=401, detail="unauthorized")

    t0 = datetime.now(timezone.utc)

    # 1) Crear job_run (SIN empresa_id; todo va en metadata)
    run_id = None
    metadata = {
        "mode": "global",
        "limite_empresas": limite_empresas,
        "limite_por_empresa": limite_por_empresa,
    }

    jr = supabase_service.table("job_runs").insert({
        "job_name": "process_outbox_global",
        "status": "running",
        "started_at": t0.isoformat(),
        "metadata": metadata,
    }).execute()

    if jr.data and len(jr.data) > 0:
        run_id = jr.data[0].get("id")

    # 2) Listar empresas con pending elegibles (next_retry_at ok)
    empresas_resp = supabase_service.rpc(
        "list_empresas_con_notificaciones_pendientes",
        {"p_limit": limite_empresas}
    ).execute()

    empresas = [r["empresa_id"] for r in (empresas_resp.data or []) if r.get("empresa_id")]

    total_enviadas = 0
    total_fallidas = 0
    total_procesadas = 0
    resumen_por_empresa = []
    error_msg = None

    try:
        for empresa_id in empresas:
            out = procesar_notificaciones_pendientes(
                supabase_service,
                empresa_id,
                limite=limite_por_empresa
            )

            total_enviadas += int(out.get("enviadas", 0))
            total_fallidas += int(out.get("fallidas", 0))
            total_procesadas += int(out.get("procesadas", 0))

            resumen_por_empresa.append({
                "empresa_id": empresa_id,
                "enviadas": int(out.get("enviadas", 0)),
                "fallidas": int(out.get("fallidas", 0)),
                "procesadas": int(out.get("procesadas", 0)),
            })

        status = "success"

    except Exception as e:
        status = "error"
        error_msg = str(e)[:500]

    # 3) Cerrar job_run (duration_s + metadata final)
    t1 = datetime.now(timezone.utc)
    duration_s = int((t1 - t0).total_seconds())

    final_metadata = {
        **metadata,
        "empresas_encontradas": len(empresas),
        "totales": {
            "enviadas": total_enviadas,
            "fallidas": total_fallidas,
            "procesadas": total_procesadas,
        },
        "por_empresa": resumen_por_empresa[:200],  # evita metadata gigante
        "error": error_msg,
    }

    if run_id:
        supabase_service.table("job_runs").update({
            "status": status,
            "finished_at": t1.isoformat(),
            "duration_s": duration_s,
            "metadata": final_metadata,
        }).eq("id", run_id).execute()

    return {
        "ok": status == "success",
        "run_id": run_id,
        "empresas": len(empresas),
        "enviadas": total_enviadas,
        "fallidas": total_fallidas,
        "procesadas": total_procesadas,
    }


@app.get("/jobs/process_outbox_global")
def jobs_process_outbox_global(
    request: Request,
    limite_empresas: int = 50,
    limite_por_empresa: int = 50,
    x_job_secret: str | None = Header(default=None),
):
    if supabase_service is None:
        raise HTTPException(status_code=500, detail="supabase_service no configurado")

    expected = os.getenv("OUTBOX_JOB_SECRET")
    if not expected:
        raise HTTPException(status_code=500, detail="OUTBOX_JOB_SECRET no configurado")

    if x_job_secret != expected:
        raise HTTPException(status_code=401, detail="unauthorized")

    t0 = datetime.now(timezone.utc)

    run_id = None
    base_meta = {
        "mode": "global",
        "limite_empresas": limite_empresas,
        "limite_por_empresa": limite_por_empresa,
    }

    # Crear job_run (tu schema real usa duration_ms, no duration_s)
    jr = supabase_service.table("job_runs").insert({
        "job_name": "process_outbox_global",
        "status": "running",
        "started_at": t0.isoformat(),
        "metadata": base_meta,
    }).execute()

    if jr.data and len(jr.data) > 0:
        run_id = jr.data[0].get("id")

    try:
        empresas_resp = supabase_service.rpc(
            "list_empresas_con_notificaciones_pendientes",
            {"p_limit": limite_empresas},
        ).execute()

        empresas = [r["empresa_id"] for r in (empresas_resp.data or []) if r.get("empresa_id")]

        total_enviadas = 0
        total_fallidas = 0
        total_procesadas = 0
        por_empresa = []
        error_msg = None

        for empresa_id in empresas:
            out = procesar_notificaciones_pendientes(
                supabase_service,
                empresa_id,
                limite=limite_por_empresa
            )

            enviadas = int(out.get("enviadas", 0))
            fallidas = int(out.get("fallidas", 0))
            procesadas = int(out.get("procesadas", 0))

            total_enviadas += enviadas
            total_fallidas += fallidas
            total_procesadas += procesadas

            por_empresa.append({
                "empresa_id": str(empresa_id),
                "enviadas": enviadas,
                "fallidas": fallidas,
                "procesadas": procesadas,
            })

        status = "success"

    except Exception as e:
        status = "error"
        empresas = []
        total_enviadas = 0
        total_fallidas = 0
        total_procesadas = 0
        por_empresa = []
        error_msg = str(e)[:500]

    t1 = datetime.now(timezone.utc)
    duration_ms = int((t1 - t0).total_seconds() * 1000)

    final_meta = {
        **base_meta,
        "empresas_encontradas": len(empresas),
        "totales": {
            "enviadas": total_enviadas,
            "fallidas": total_fallidas,
            "procesadas": total_procesadas,
        },
        "por_empresa": por_empresa[:200],
        "error": error_msg,
    }

    if run_id:
        supabase_service.table("job_runs").update({
            "status": status,
            "finished_at": t1.isoformat(),
            "duration_ms": duration_ms,
            "metadata": final_meta,
        }).eq("id", run_id).execute()

    return {
        "ok": status == "success",
        "run_id": run_id,
        "empresas": len(empresas),
        "enviadas": total_enviadas,
        "fallidas": total_fallidas,
        "procesadas": total_procesadas,
    }


from pydantic import BaseModel
from typing import Optional

class ObligacionCreate(BaseModel):
    titulo: str
    descripcion: Optional[str] = None
    tipo: Optional[str] = None
    fecha_limite: str  # "YYYY-MM-DD"

    # NUEVO core
    entidad_id: Optional[str] = None

    # LEGACY (temporal)
    vehiculo_id: Optional[str] = None

    responsable_auth_id: Optional[str] = None
    metadata: Optional[dict] = None

class CambiarEstadoPayload(BaseModel):
    nuevo_estado: str
    comentario: Optional[str] = None

class CambiarResponsablePayload(BaseModel):
    nuevo_responsable_auth_id: Optional[str] = None


class ObligacionCreate(BaseModel):
    titulo: str
    descripcion: Optional[str] = None
    tipo: Optional[str] = None
    fecha_limite: str  # "YYYY-MM-DD"

    # ✅ Core (nuevo)
    entidad_id: Optional[str] = None

    # 🧩 Legacy temporal (para compatibilidad con UI vieja)
    vehiculo_id: Optional[str] = None

    responsable_auth_id: Optional[str] = None
    metadata: Optional[dict] = None


@app.post("/obligaciones")
def crear_obligacion(payload: ObligacionCreate, request: Request):
    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    user = usuario_actual(request)
    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing in session")

    # -----------------------------
    # Resolver entidad_id (core) con fallback legacy vehiculo_id
    # -----------------------------
    entidad_id = (payload.entidad_id or "").strip() or None
    vehiculo_id = (payload.vehiculo_id or "").strip() or None

    if not entidad_id and vehiculo_id:
        # 1) leer vehiculo (RLS)
        v = (
            sb.table("vehiculos")
            .select("id,empresa_id,matricula")
            .eq("id", vehiculo_id)
            .eq("empresa_id", empresa_id)
            .limit(1)
            .execute()
        )
        vrow = (v.data or [None])[0]
        if not vrow:
            raise HTTPException(status_code=400, detail="vehiculo_id inválido o no autorizado")

        # 2) buscar entidad_regulada correspondiente (RLS)
        e = (
            sb.table("entidades_reguladas")
            .select("id")
            .eq("empresa_id", empresa_id)
            .eq("tipo", "vehiculo")
            .eq("codigo", vrow.get("matricula"))
            .limit(1)
            .execute()
        )
        erow = (e.data or [None])[0]
        if not erow:
            raise HTTPException(status_code=400, detail="No existe entidad_regulada para ese vehículo")

        entidad_id = erow["id"]

    # ✅ Guardrail: no permitir obligaciones sin entidad
    if not entidad_id:
        raise HTTPException(status_code=400, detail="entidad_id requerido (o vehiculo_id legacy)")

    actor_auth_id = get_auth_user_id_from_session(request)
    actor_username = request.session.get("user")

    # ✅ Calcular SLA interno (internal_deadline) según política por tipo
    internal_deadline = None
    criticidad = "media"   # ✅ default seguro
    internal_deadline = None
    try:
        tipo_norm = (payload.tipo or "general").strip().lower()
        pol_tipo = get_obligacion_politica(empresa_id, tipo_norm)  # ✅ usa el normalizado
        criticidad = (pol_tipo.get("criticidad") or "media").lower()

        sla_dias_antes = pol_tipo.get("sla_dias_antes")
        if sla_dias_antes is not None:
            sla_dias_antes = int(sla_dias_antes)
            fl = datetime.fromisoformat(str(payload.fecha_limite)[:10]).date()
            internal_deadline = (fl - timedelta(days=sla_dias_antes)).isoformat()
    except Exception as e:
        logger.warning("No se pudo calcular internal_deadline: %s", str(e)[:120])

    data = {
        "empresa_id": empresa_id,
        "titulo": (payload.titulo or "").strip(),
        "descripcion": payload.descripcion,
        "tipo": payload.tipo,
        "fecha_limite": payload.fecha_limite,
        "criticidad_snapshot": criticidad,

        # ✅ Core
        "entidad_id": entidad_id,

        "creador_auth_id": actor_auth_id,
        "responsable_auth_id": payload.responsable_auth_id,
        "internal_deadline": internal_deadline,
        "incumple_sla": False,
        "metadata": payload.metadata or {}
    }

    # 1) Insert obligación
    try:
        resp = sb.table("obligaciones").insert(data).execute()
    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            raise HTTPException(status_code=401, detail="Sesión expirada, vuelve a iniciar sesión")
        raise HTTPException(status_code=500, detail=str(e)[:200])

    row = (resp.data or [None])[0]
    if not row:
        raise HTTPException(status_code=500, detail="Insert failed")

    try:
        recalcular_score_y_notificar_entidad(sb, empresa_id, entidad_id)
    except Exception as e:
        logger.warning("Score entidad no se pudo recalcular: %s", str(e)[:200])

    # 2) Audit log (transversal)
    log_event(
        sb=sb,
        empresa_id=empresa_id,
        action="create",
        entity_type="obligaciones",
        entity_id=str(row.get("id")),
        metadata={
            "titulo": row.get("titulo"),
            "fecha_limite": str(row.get("fecha_limite")),
            "responsable_auth_id": row.get("responsable_auth_id"),
            "entidad_id": entidad_id,  # ✅ clave para motor defendible
        },
        request=request
    )

    # 3) Evento estructurado (timeline)
    try:
        sb.table("obligacion_eventos").insert({
            "empresa_id": empresa_id,
            "obligacion_id": row.get("id"),
            "tipo_evento": "created",
            "actor_auth_id": actor_auth_id,
            "actor_username": actor_username,
            "datos": {
                "titulo": row.get("titulo"),
                "fecha_limite": str(row.get("fecha_limite")),
                "responsable_auth_id": row.get("responsable_auth_id"),
                "entidad_id": entidad_id,
            }
        }).execute()
    except Exception as e:
        logger.warning("No se pudo insertar obligacion_eventos: %s", str(e)[:200])

    return {"ok": True, "obligacion": row}


@app.patch("/obligaciones/{obligacion_id}/estado")
def cambiar_estado_obligacion(obligacion_id: str, payload: CambiarEstadoPayload, request: Request):

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    user = usuario_actual(request)
    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    estados_validos = {"pendiente", "en_proceso", "resuelta", "incumplida"}

    nuevo_estado = (payload.nuevo_estado or "").strip().lower()

    if nuevo_estado not in estados_validos:
        raise HTTPException(status_code=400, detail="Estado inválido")

    # 1️⃣ Leer estado actual (RLS aplica)
    res = (
        sb.table("obligaciones")
        .select("estado")
        .eq("id", obligacion_id)
        .eq("empresa_id", empresa_id)
        .limit(1)
        .execute()
    )

    row = (res.data or [None])[0]
    if not row:
        raise HTTPException(status_code=404, detail="No encontrada o no autorizada")

    estado_anterior = row.get("estado")

    # 🔒 Regla de negocio: si se marca como resuelta
    if nuevo_estado == "resuelta":

        tiene_comentario = bool((payload.comentario or "").strip())

        # comprobar evidencias existentes
        ev = (
            sb.table("obligacion_evidencias")
            .select("id")
            .eq("obligacion_id", obligacion_id)
            .limit(1)
            .execute()
        )

        tiene_evidencia = bool(ev.data)

        if not tiene_comentario and not tiene_evidencia:
            raise HTTPException(
                status_code=400,
                detail="Para marcar como resuelta debes añadir comentario o evidencia"
            )

    # 2️⃣ Actualizar estado
    update_payload = {
        "estado": nuevo_estado,
        "actualizado_en": utc_now_iso()
    }

    # Si pasa a resuelta por primera vez, guardamos resolved_at
    if nuevo_estado == "resuelta":
        update_payload["resolved_at"] = utc_now_iso()

    sb.table("obligaciones").update(update_payload)\
      .eq("id", obligacion_id)\
      .eq("empresa_id", empresa_id)\
      .execute()


    # 3️⃣ Auditoría
    log_event(
        sb=sb,
        empresa_id=empresa_id,
        action="status_change",
        entity_type="obligaciones",
        entity_id=obligacion_id,
        metadata={
            "estado_anterior": estado_anterior,
            "estado_nuevo": nuevo_estado,
            "comentario": payload.comentario
        },
        request=request
    )

    # ✅ Evento estructurado (timeline)
    try:
        sb.table("obligacion_eventos").insert({
            "empresa_id": empresa_id,
            "obligacion_id": obligacion_id,
            "tipo_evento": "status_change",
            "actor_auth_id": get_auth_user_id_from_session(request),
            "actor_username": request.session.get("user"),
            "datos": {
                "estado_anterior": estado_anterior,
                "estado_nuevo": nuevo_estado,
                "comentario": payload.comentario
            }
        }).execute()
    except Exception as e:
        logger.warning("No se pudo insertar evento status_change: %s", str(e)[:200])

    return {
        "ok": True,
        "estado_anterior": estado_anterior,
        "estado_nuevo": nuevo_estado
    }

class EvidenciaPayload(BaseModel):
    tipo: str  # "nota" | "link"
    contenido: str
    nombre_archivo: Optional[str] = None
    metadata: Optional[dict] = None


@app.post("/obligaciones/{obligacion_id}/evidencia")
def agregar_evidencia(obligacion_id: str, payload: EvidenciaPayload, request: Request):

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    user = usuario_actual(request)
    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    tipos_validos = {"nota", "link"}

    if payload.tipo not in tipos_validos:
        raise HTTPException(status_code=400, detail="Tipo inválido")

    # Insertar evidencia (RLS aplica)
    res = sb.table("obligacion_evidencias").insert({
        "empresa_id": empresa_id,
        "obligacion_id": obligacion_id,
        "tipo": payload.tipo,
        "contenido": payload.contenido,
        "nombre_archivo": payload.nombre_archivo,
        "subido_por_auth_id": get_auth_user_id_from_session(request),
        "metadata": payload.metadata or {}
    }).execute()

    row = (res.data or [None])[0]
    if not row:
        raise HTTPException(status_code=500, detail="No se pudo insertar evidencia")

    # Auditoría
    log_event(
        sb=sb,
        empresa_id=empresa_id,
        action="evidencia_added",
        entity_type="obligaciones",
        entity_id=obligacion_id,
        metadata={
            "evento": "evidencia_agregada",
            "tipo": payload.tipo
        },
        request=request
    )

    # ✅ Evento estructurado: evidencia_agregada
    try:
        sb.table("obligacion_eventos").insert({
            "empresa_id": empresa_id,
            "obligacion_id": obligacion_id,
            "tipo_evento": "evidencia_agregada",
            "actor_auth_id": get_auth_user_id_from_session(request),
            "actor_username": request.session.get("user"),
            "datos": {
                "evidencia_id": row.get("id"),
                "tipo": row.get("tipo"),
                "nombre_archivo": row.get("nombre_archivo"),
                "contenido": row.get("contenido")
            }
        }).execute()
    except Exception as e:
        logger.warning("No se pudo insertar evento evidencia_agregada: %s", str(e)[:200])

    return {"ok": True, "evidencia": row}


@app.get("/obligaciones/{obligacion_id}/eventos")
def listar_eventos_obligacion(obligacion_id: str, request: Request):

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    user = usuario_actual(request)
    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    try:
        res = (
            sb.table("obligacion_eventos")
            .select("id,tipo_evento,actor_username,datos,creado_en")
            .eq("empresa_id", empresa_id)
            .eq("obligacion_id", obligacion_id)
            .order("creado_en", desc=False)
            .execute()
        )
    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            raise HTTPException(status_code=401, detail="Sesión expirada")
        raise

    return {
        "ok": True,
        "obligacion_id": obligacion_id,
        "eventos": res.data or []
    }


@app.patch("/obligaciones/{obligacion_id}/responsable")
def cambiar_responsable_obligacion(
    obligacion_id: str,
    payload: CambiarResponsablePayload,
    request: Request
):

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    user = usuario_actual(request)
    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    actor_auth_id = get_auth_user_id_from_session(request)

    # 1️⃣ Leer responsable actual
    res = (
        sb.table("obligaciones")
        .select("responsable_auth_id")
        .eq("id", obligacion_id)
        .eq("empresa_id", empresa_id)
        .limit(1)
        .execute()
    )

    row = (res.data or [None])[0]
    if not row:
        raise HTTPException(status_code=404, detail="No encontrada o no autorizada")

    responsable_anterior = row.get("responsable_auth_id")
    nuevo_responsable = payload.nuevo_responsable_auth_id

    # 2️⃣ Actualizar
    sb.table("obligaciones").update({
        "responsable_auth_id": nuevo_responsable,
        "actualizado_en": utc_now_iso()
    }).eq("id", obligacion_id).eq("empresa_id", empresa_id).execute()

    # 3️⃣ Auditoría transversal
    log_event(
        sb=sb,
        empresa_id=empresa_id,
        action="responsable_change",
        entity_type="obligaciones",
        entity_id=obligacion_id,
        metadata={
            "responsable_anterior": responsable_anterior,
            "responsable_nuevo": nuevo_responsable
        },
        request=request
    )

    # 4️⃣ Evento estructurado
    try:
        sb.table("obligacion_eventos").insert({
            "empresa_id": empresa_id,
            "obligacion_id": obligacion_id,
            "tipo_evento": "responsable_cambiado",
            "actor_auth_id": actor_auth_id,
            "actor_username": request.session.get("user"),
            "datos": {
                "responsable_anterior": responsable_anterior,
                "responsable_nuevo": nuevo_responsable
            }
        }).execute()
    except Exception as e:
        logger.warning("No se pudo insertar evento responsable_cambiado: %s", str(e)[:200])

    return {
        "ok": True,
        "responsable_anterior": responsable_anterior,
        "responsable_nuevo": nuevo_responsable
    }


from postgrest.exceptions import APIError

@app.get("/vehiculos")
def listar_vehiculos(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # ✅ Tu helper ya refresca JWT si está expirado
    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        # si no tiene empresa, no es login: es configuración
        return RedirectResponse(url="/config?force=1", status_code=303)

    try:
        res = (
            sb.table("entidades_reguladas")
            .select("id,empresa_id,tipo,nombre,codigo,metadata,activo,creado_en")
            .eq("empresa_id", empresa_id)
            .eq("tipo", "vehiculo")
            .order("creado_en", desc=True)
            .execute()
        )
        entidades = res.data or []

        # Adaptador para NO tocar el template vehiculos.html
        vehiculos = []
        for e in entidades:
            md = e.get("metadata") or {}
            vehiculos.append({
                "id": e.get("id"),
                "empresa_id": e.get("empresa_id"),
                "matricula": e.get("codigo") or e.get("nombre"),
                "marca": md.get("marca"),
                "modelo": md.get("modelo"),
                "anio": md.get("anio"),
                "activo": e.get("activo", True),
                "creado_en": e.get("creado_en"),
            })

    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)

        vehiculos = []
        # opcional: mostrar error en UI
        # return templates.TemplateResponse("vehiculos.html", {
        #     "request": request,
        #     "user": user,
        #     "rol": get_rol(user),
        #     "vehiculos": [],
        #     "error": str(e)[:160]
        # })

    return templates.TemplateResponse("vehiculos.html", {
        "request": request,
        "user": user,
        "rol": get_rol(user),
        "vehiculos": vehiculos
    })

@app.post("/entidades")
def crear_entidad(payload: EntidadCreate, request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    tipo = (payload.tipo or "").strip().lower()
    nombre = (payload.nombre or "").strip()
    codigo = (payload.codigo or "").strip() or None
    metadata = payload.metadata or {}
    activo = True if payload.activo is None else bool(payload.activo)

    # Guardrails: evita basura (esto te hace defendible)
    if tipo not in {"vehiculo", "subcontrata", "centro", "activo", "contrato"}:
        raise HTTPException(status_code=400, detail="tipo no permitido")

    if not nombre:
        raise HTTPException(status_code=400, detail="nombre requerido")

    # Normalización útil para vehiculos
    if tipo == "vehiculo" and codigo:
        codigo = codigo.upper().replace(" ", "").replace("-", "-")

    data = {
        "empresa_id": empresa_id,
        "tipo": tipo,
        "nombre": nombre,
        "codigo": codigo,
        "metadata": metadata,
        "activo": activo,
    }

    try:
        resp = sb.table("entidades_reguladas").insert(data).execute()
    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)
        # si tienes unique por empresa+tipo+codigo, caerá aquí
        raise HTTPException(status_code=400, detail=str(e)[:200])

    row = (resp.data or [None])[0]
    if not row:
        raise HTTPException(status_code=500, detail="Insert failed")

    # Audit log (opcional pero recomendado)
    try:
        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="create",
            entity_type="entidades_reguladas",
            entity_id=str(row.get("id")),
            metadata={"tipo": tipo, "nombre": nombre, "codigo": codigo},
            request=request
        )
    except Exception:
        pass

    return {"ok": True, "entidad": row}


@app.get("/entidades/nueva")
def form_entidad_nueva(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("entidad_nueva.html", {
        "request": request,
        "user": user,
        "rol": get_rol(user),
    })


@app.post("/entidades/nueva")
def submit_entidad_nueva(
    request: Request,
    tipo: str = Form(...),
    nombre: str = Form(...),
    codigo: str = Form(None),
    metadata: str = Form(""),
    activo: str = Form("true"),
):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    tipo = (tipo or "").strip().lower()
    nombre = (nombre or "").strip()
    codigo = (codigo or "").strip() or None
    activo_bool = (activo == "true")

    if tipo not in {"vehiculo", "subcontrata", "centro", "activo", "contrato"}:
        raise HTTPException(status_code=400, detail="tipo no permitido")

    md = {}
    if (metadata or "").strip():
        try:
            md = json.loads(metadata)
            if not isinstance(md, dict):
                raise ValueError("metadata debe ser objeto JSON")
        except Exception:
            raise HTTPException(status_code=400, detail="metadata JSON inválido")

    data = {
        "empresa_id": empresa_id,
        "tipo": tipo,
        "nombre": nombre,
        "codigo": codigo,
        "metadata": md,
        "activo": activo_bool,
    }

    try:
        resp = sb.table("entidades_reguladas").insert(data).execute()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)[:200])

    row = (resp.data or [None])[0]
    if not row:
        raise HTTPException(status_code=500, detail="Insert failed")

    # después de crear, te mando a /vehiculos si era vehiculo
    if tipo == "vehiculo":
        return RedirectResponse(url="/vehiculos", status_code=303)

    return RedirectResponse(url="/entidades/nueva", status_code=303)


@app.get("/obligaciones/nueva")
def form_obligacion_nueva(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    # Cargar vehículos (entidades tipo vehiculo)
    res = (
        sb.table("entidades_reguladas")
        .select("id,nombre,codigo")
        .eq("empresa_id", empresa_id)
        .eq("tipo", "vehiculo")
        .order("codigo", desc=False)
        .execute()
    )
    vehiculos = res.data or []

    return templates.TemplateResponse("obligacion_nueva.html", {
        "request": request,
        "user": user,
        "rol": get_rol(user),
        "vehiculos": vehiculos,
    })


@app.post("/obligaciones/nueva")
def submit_obligacion_nueva(
    request: Request,
    entidad_id: str = Form(...),
    titulo: str = Form(...),
    tipo: str = Form("general"),
    fecha_limite: str = Form(...),
    descripcion: str = Form(""),
    metadata: str = Form(""),
):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    entidad_id = (entidad_id or "").strip()
    if not entidad_id:
        raise HTTPException(status_code=400, detail="entidad_id requerido")

    titulo = (titulo or "").strip()
    if not titulo:
        raise HTTPException(status_code=400, detail="titulo requerido")

    tipo_norm = (tipo or "general").strip().lower() or "general"

    # Validar metadata JSON
    md = {}
    if (metadata or "").strip():
        try:
            md = json.loads(metadata)
            if not isinstance(md, dict):
                raise ValueError("metadata debe ser objeto JSON")
        except Exception:
            raise HTTPException(status_code=400, detail="metadata JSON inválido")

    actor_auth_id = get_auth_user_id_from_session(request)
    actor_username = request.session.get("user")

    # 1) Política (criticidad + SLA)
    pol_tipo = {}
    try:
        pol_tipo = get_obligacion_politica(empresa_id, tipo_norm) or {}
    except Exception as e:
        logger.warning("No se pudo cargar politica (%s): %s", tipo_norm, str(e)[:160])

    criticidad = (pol_tipo.get("criticidad") or "media").lower()

    # 2) SLA interno
    internal_deadline = None
    try:
        sla_dias_antes = pol_tipo.get("sla_dias_antes")
        if sla_dias_antes is not None:
            sla_dias_antes = int(sla_dias_antes)
            fl = datetime.fromisoformat(str(fecha_limite)[:10]).date()
            internal_deadline = (fl - timedelta(days=sla_dias_antes)).isoformat()
    except Exception as e:
        logger.warning("No se pudo calcular internal_deadline: %s", str(e)[:160])

    data = {
        "empresa_id": empresa_id,
        "titulo": titulo,
        "descripcion": (descripcion or "").strip() or None,
        "tipo": tipo_norm,
        "fecha_limite": fecha_limite,
        "entidad_id": entidad_id,
        "creador_auth_id": actor_auth_id,
        "responsable_auth_id": None,
        "internal_deadline": internal_deadline,
        "incumple_sla": False,
        "metadata": md,
        "criticidad_snapshot": criticidad,  # ✅ snapshot
    }

    # 3) Insert obligación
    try:
        resp = sb.table("obligaciones").insert(data).execute()
    except Exception as e:
        msg = str(e).lower()
        if "jwt expired" in msg or "pgrst303" in msg:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)
        raise HTTPException(status_code=400, detail=str(e)[:200])

    row = (resp.data or [None])[0]
    if not row:
        raise HTTPException(status_code=500, detail="Insert failed")

    # 4) Audit + evento (no romper UX si falla)
    try:
        log_event(
            sb=sb,
            empresa_id=empresa_id,
            action="create",
            entity_type="obligaciones",
            entity_id=str(row.get("id")),
            metadata={
                "titulo": row.get("titulo"),
                "tipo": row.get("tipo"),
                "fecha_limite": str(row.get("fecha_limite")),
                "entidad_id": entidad_id,
                "criticidad_snapshot": criticidad,
            },
            request=request
        )
    except Exception as e:
        logger.warning("Audit log falló: %s", str(e)[:160])

    try:
        sb.table("obligacion_eventos").insert({
            "empresa_id": empresa_id,
            "obligacion_id": row.get("id"),
            "tipo_evento": "created",
            "actor_auth_id": actor_auth_id,
            "actor_username": actor_username,
            "datos": {
                "titulo": row.get("titulo"),
                "tipo": row.get("tipo"),
                "fecha_limite": str(row.get("fecha_limite")),
                "entidad_id": entidad_id,
                "criticidad_snapshot": criticidad
            }
        }).execute()
    except Exception as e:
        logger.warning("No se pudo insertar obligacion_eventos: %s", str(e)[:200])

    # 5) ✅ Score + notificación (Paso 6) — no romper UX si falla
    try:
        recalcular_score_y_notificar_entidad(sb, empresa_id, entidad_id)
    except Exception as e:
        logger.warning("Score entidad no se pudo recalcular: %s", str(e)[:200])

    # 6) Redirigir al detalle de entidad (mejor UX que volver al dashboard)
    return RedirectResponse(url=f"/entidades/{entidad_id}", status_code=303)


@app.get("/entidades/{entidad_id}")
def ver_entidad(entidad_id: str, request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    sb = supabase_user_client(request)
    if sb is None:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    # 1) Cargar entidad (RLS)
    ent_res = (
        sb.table("entidades_reguladas")
        .select("id,empresa_id,tipo,nombre,codigo,metadata,activo,creado_en")
        .eq("id", entidad_id)
        .eq("empresa_id", empresa_id)
        .limit(1)
        .execute()
    )
    entidad = (ent_res.data or [None])[0]
    if not entidad:
        raise HTTPException(status_code=404, detail="Entidad no encontrada")

    # 2) Obligaciones de la entidad (IMPORTANTE: incluir criticidad_snapshot)
    obl_res = (
        sb.table("obligaciones")
        .select(
            "id,titulo,tipo,estado,fecha_limite,internal_deadline,incumple_sla,resolved_at,creado_en,metadata,criticidad_snapshot"
        )
        .eq("empresa_id", empresa_id)
        .eq("entidad_id", entidad_id)
        .order("fecha_limite", desc=False)
        .execute()
    )
    obligaciones = obl_res.data or []

    # 3) Evidencias (por obligación)
    ids = [o["id"] for o in obligaciones if o.get("id")]
    evidencias = []
    if ids:
        ev_res = (
            sb.table("obligacion_evidencias")
            .select("id,obligacion_id,tipo,nombre_archivo,contenido,subido_por_auth_id,creado_en,metadata")
            .eq("empresa_id", empresa_id)
            .in_("obligacion_id", ids)
            .order("creado_en", desc=True)
            .execute()
        )
        evidencias = ev_res.data or []

    # 4) Timeline de eventos (últimos 100)
    eventos = []
    if ids:
        evts_res = (
            sb.table("obligacion_eventos")
            .select("id,obligacion_id,tipo_evento,actor_auth_id,actor_username,datos,creado_en")
            .eq("empresa_id", empresa_id)
            .in_("obligacion_id", ids)
            .order("creado_en", desc=True)
            .limit(100)
            .execute()
        )
        eventos = evts_res.data or []

    # 5) KPI riesgo (OPERATIVO / EN_RIESGO / BLOQUEADO)
    hoy = utc_now().date()

    def parse_date(x):
        if not x:
            return None
        try:
            return parser.parse(str(x)).date()
        except Exception:
            return None

    abiertas = [o for o in obligaciones if o.get("estado") != "resuelta"]
    resueltas = [o for o in obligaciones if o.get("estado") == "resuelta"]

    vencidas = []
    vencen_7d = []
    fuera_sla = []

    for o in abiertas:
        fl = parse_date(o.get("fecha_limite"))
        crit = (o.get("criticidad_snapshot") or "media").lower()

        if o.get("incumple_sla") is True and crit in ("critica", "alta"):
            fuera_sla.append(o)

        if fl:
            if fl < hoy and crit in ("critica", "alta"):
                vencidas.append(o)
            elif hoy <= fl <= (hoy + timedelta(days=7)) and crit in ("critica", "alta"):
                vencen_7d.append(o)

    def is_alta(o):
        c = (o.get("criticidad_snapshot") or "media").lower()
        return c in ("critica", "alta")

    criticas_abiertas = [
        o for o in abiertas
        if (o.get("criticidad_snapshot") or "media").lower() == "critica"
    ]

    # 1) Estado OPERATIVO (inmediato)
    if vencidas or fuera_sla:
        estado_operativo = "BLOQUEADO"
    elif vencen_7d:
        estado_operativo = "EN_RIESGO"
    else:
        estado_operativo = "OPERATIVO"

    # 2) Estado REGULATORIO (disciplina)
    if vencidas or fuera_sla:
        estado_regulatorio = "NO_CUMPLE"
    elif criticas_abiertas or len(abiertas) >= 5:
        estado_regulatorio = "EN_CONTROL"
    else:
        estado_regulatorio = "CUMPLE"

    # Conservador: cualquier "critica" abierta => EN_RIESGO
    criticas_abiertas = [
        o for o in abiertas
        if (o.get("criticidad_snapshot") or "media").lower() == "critica"
    ]

    if vencidas or fuera_sla:
        riesgo = "BLOQUEADO"
    elif vencen_7d or criticas_abiertas or len(abiertas) >= 5:
        riesgo = "EN_RIESGO"
    else:
        riesgo = "OPERATIVO"

    # Indexar evidencias por obligacion_id para el template
    evid_por_ob = {}
    for ev in evidencias:
        evid_por_ob.setdefault(str(ev.get("obligacion_id")), []).append(ev)

    # ✅ RETURN FINAL (esto evita el "null")
    return templates.TemplateResponse("entidad_detalle.html", {
        "request": request,
        "user": user,
        "rol": get_rol(user),
        "entidad": entidad,
        "estado_operativo": estado_operativo,
        "estado_regulatorio": estado_regulatorio,
        "abiertas": abiertas,
        "resueltas": resueltas,
        "evid_por_ob": evid_por_ob,
        "eventos": eventos
    })


@app.get("/debug_recalc_score/{entidad_id}")
def debug_recalc_score(entidad_id: str, request: Request):
    user = usuario_actual(request)
    if not user:
        raise HTTPException(status_code=401, detail="No session")

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    # 👇 fuerza el cálculo
    recalcular_score_y_notificar_entidad(sb, empresa_id, entidad_id)

    return {"ok": True, "empresa_id": empresa_id, "entidad_id": entidad_id}



@app.get("/debug_generar_recordatorios")
def debug_generar_recordatorios(request: Request):
    user = usuario_actual(request)
    if not user:
        raise HTTPException(status_code=401, detail="No session")

    sb = supabase_user_client(request)
    if sb is None:
        raise HTTPException(status_code=401, detail="No session")

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        raise HTTPException(status_code=400, detail="empresa_id missing")

    out = generar_recordatorios_obligaciones(sb, empresa_id, request, dias_lista=(1,7,30), canal="email")
    return out


def utc_now():
    return datetime.now(timezone.utc)

def utc_now_iso():
    return utc_now().isoformat()


EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


def normalizar_destinatarios(destinatarios: list[str]) -> tuple[list[str], list[str]]:
    """
    Devuelve (validos_unicos, invalidos).
    - Normaliza: strip + lowercase
    - Dedup: conserva orden
    """
    if not destinatarios:
        return [], []

    vistos = set()
    validos = []
    invalidos = []

    for d in destinatarios:
        d_norm = (d or "").strip().lower()
        if not d_norm:
            continue
        if d_norm in vistos:
            continue
        vistos.add(d_norm)

        if email_valido(d_norm):
            validos.append(d_norm)
        else:
            invalidos.append(d_norm)

    return validos, invalidos


def email_valido(email: str) -> bool:
    if not email:
        return False
    email = email.strip()
    if len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def procesar_notificaciones_pendientes(sb, empresa_id: str, limite: int = 50):
    """
    Worker enterprise:
    - Claim atómico via RPC (FOR UPDATE SKIP LOCKED) => pending -> processing
    - Data Quality: normaliza/dedup/valida destinatarios antes de enviar
    - Audita dq en metadata
    - Retry/backoff solo para errores temporales
    - Limpia processing_started_en al finalizar
    """

    # 1) Claim atómico vía RPC (respeta next_retry_at en la función SQL)
    claim = sb.rpc("claim_notificaciones", {
        "p_empresa_id": empresa_id,
        "p_limit": limite
    }).execute()

    filas = claim.data or []
    if not filas:
        return {"enviadas": 0, "fallidas": 0, "procesadas": 0}

    enviadas = 0
    fallidas = 0

    for n in filas:
        notif_id = n.get("id")
        canal = (n.get("canal") or "").lower()
        destinatarios = n.get("destinatarios") or []
        tipo_aviso = n.get("tipo_aviso") or "aviso"
        md = n.get("metadata") or {}

        try:
            if not notif_id:
                raise Exception("Notificación sin id")

            if canal != "email":
                raise Exception(f"Canal no soportado: {canal}")

            # --- Data Quality: normaliza/dedup/valida ---
            validos, invalidos = normalizar_destinatarios(destinatarios)

            if not validos:
                # Permanente: no hay ningún destinatario válido
                raise ResendError(422, f"Invalid email(s) (prevalidation): {invalidos}")

            # Auditar dq en metadata (sin romper metadata existente)
            md_out = dict(md or {})
            md_out["dq"] = {
                "destinatarios_original": destinatarios,
                "destinatarios_validos": validos,
                "destinatarios_invalidos": invalidos,
                "dedupe_aplicado": True,
            }
            md = md_out

            # Persistir metadata dq para trazabilidad (aunque luego falle el envío)
            sb.table("notificaciones").update({
                "metadata": md,
            }).eq("id", notif_id).execute()

            # --- Construcción de mensaje (mínimo, puedes enriquecer) ---
            titulo = md.get("titulo") or "Obligación"
            fecha_obj = md.get("fecha_limite") or ""
            asunto = f"[{tipo_aviso}] {titulo}".strip()

            cuerpo = (
                f"Recordatorio ({tipo_aviso})\n\n"
                f"Título: {titulo}\n"
                f"Fecha límite: {fecha_obj}\n\n"
            )

            provider = "resend"
            provider_id = None

            # Enviar solo a válidos (ya normalizados)
            for destino in validos:
                provider_id = enviar_email(destino, asunto, cuerpo)

            # Marcar sent
            supabase_service.rpc("mark_notificacion_sent", {
                "p_id": notif_id,
                "p_provider": provider,
                "p_provider_id": provider_id,
            }).execute()

            enviadas += 1

        except Exception as e:
            # Clasificación permanente vs temporal
            permanente = False
            status_code = None

            if isinstance(e, ResendError):
                status_code = e.status_code
                # Permanentes: 4xx excepto 429
                if 400 <= status_code < 500 and status_code != 429:
                    permanente = True

            nuevo_intentos = (n.get("intentos") or 0) + 1

            if permanente:
                # Error definitivo: no reintentar
                sb.table("notificaciones").update({
                    "status": NOTIF_STATUS_ERROR,
                    "error": str(e)[:500],
                    "provider": "resend",
                    "provider_id": None,
                    "intentos": nuevo_intentos,
                    "next_retry_at": None,
                }).eq("id", notif_id).execute()

                fallidas += 1
            else:
                # Error temporal: reintentar con backoff
                minutos = min(60, 5 * nuevo_intentos)

                sb.table("notificaciones").update({
                    "status": NOTIF_STATUS_PENDING if nuevo_intentos < 5 else NOTIF_STATUS_ERROR,
                    "error": str(e)[:500],
                    "provider": "resend",
                    "provider_id": None,
                    "intentos": nuevo_intentos,
                    "next_retry_at": (utc_now() + timedelta(minutes=minutos)).isoformat(),
                }).eq("id", notif_id).execute()

                fallidas += 1

    return {
        "enviadas": enviadas,
        "fallidas": fallidas,
        "procesadas": len(filas),
    }


@app.get("/debug_enviar_pendientes")
def debug_enviar_pendientes(request: Request, limite: int = 50):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="supabase_service no configurado")

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    out = procesar_notificaciones_pendientes(supabase_service, empresa_id, limite=limite)
    return {"ok": True, **out}


@app.get("/metrics/notificaciones")
def metrics_notificaciones(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="supabase_service no configurado")

    empresa_id = get_empresa_id(user)
    if not empresa_id:
        return RedirectResponse(url="/config?force=1", status_code=303)

    # Ventana temporal: últimas 24h (evita contaminar SLA con histórico)
    since = (datetime.now(tz=timezone.utc) - timedelta(hours=24)).isoformat()

    resp = (
        supabase_service.table("notificaciones")
        .select("status, creado_en, processing_started_en, enviado_en, intentos")
        .eq("empresa_id", empresa_id)
        .gte("creado_en", since)
        .execute()
    )

    rows = resp.data or []

    total = len(rows)
    sent = sum(1 for r in rows if r.get("status") == "sent")
    err = sum(1 for r in rows if r.get("status") == "error")
    pending = sum(1 for r in rows if r.get("status") == "pending")
    processing_count = sum(1 for r in rows if r.get("status") == "processing")

    retry_total = sum((r.get("intentos") or 0) for r in rows)

    # Latencias
    cola_latencias = []
    envio_latencias = []
    end_to_end_latencias = []

    for r in rows:
        try:
            creado_s = r.get("creado_en")
            proc_s = r.get("processing_started_en")
            enviado_s = r.get("enviado_en")

            creado_dt = datetime.fromisoformat(creado_s.replace("Z", "+00:00")) if creado_s else None
            proc_dt = datetime.fromisoformat(proc_s.replace("Z", "+00:00")) if proc_s else None
            enviado_dt = datetime.fromisoformat(enviado_s.replace("Z", "+00:00")) if enviado_s else None

            if creado_dt and proc_dt:
                cola_latencias.append((proc_dt - creado_dt).total_seconds())

            if proc_dt and enviado_dt:
                envio_latencias.append((enviado_dt - proc_dt).total_seconds())

            if creado_dt and enviado_dt:
                end_to_end_latencias.append((enviado_dt - creado_dt).total_seconds())

        except Exception:
            pass

    latencia_media_cola = sum(cola_latencias) / len(cola_latencias) if cola_latencias else 0
    latencia_media_envio = sum(envio_latencias) / len(envio_latencias) if envio_latencias else 0
    latencia_media = sum(end_to_end_latencias) / len(end_to_end_latencias) if end_to_end_latencias else 0

    # Stuck real: processing > 5 min
    umbral_segundos = 5 * 60
    ahora = datetime.now(tz=timezone.utc)

    stuck = 0
    for r in rows:
        if r.get("status") != "processing":
            continue
        ps = r.get("processing_started_en")
        if not ps:
            continue
        try:
            ps_dt = datetime.fromisoformat(ps.replace("Z", "+00:00"))
            if (ahora - ps_dt).total_seconds() > umbral_segundos:
                stuck += 1
        except Exception:
            pass

    return {
        "window_hours": 24,
        "total": total,
        "sent": sent,
        "error": err,
        "pending": pending,
        "processing": processing_count,
        "retry_total": retry_total,
        "latencia_media_cola_segundos": round(latencia_media_cola, 2),
        "latencia_media_envio_segundos": round(latencia_media_envio, 2),
        "latencia_media_segundos": round(latencia_media, 2),
        "stuck_processing": stuck,
        "stuck_threshold_seconds": umbral_segundos,
    }