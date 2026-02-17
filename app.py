from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from pathlib import Path
from pypdf import PdfReader

from fastapi import Header, HTTPException
import re, json, os
from urllib.parse import quote
import jwt
import logging
from datetime import datetime, timedelta
from dateutil import parser

from passlib.context import CryptContext
import yagmail

from fastapi.responses import StreamingResponse
import csv
from io import StringIO

import secrets
import string

from supabase import Client
from io import BytesIO
from supabase import create_client
from dotenv import load_dotenv

import base64

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


supabase_service = None
supabase_anon = None

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase_service = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

if SUPABASE_URL and SUPABASE_ANON_KEY:
    supabase_anon = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
else:
    print("⚠️ SUPABASE_URL o SUPABASE_ANON_KEY no están configuradas en el entorno.")

# ✅ alias DESPUÉS de crear el cliente
supabase = supabase_service


if SUPABASE_URL and not SUPABASE_URL.startswith("https://"):
    print("⚠️ SUPABASE_URL no empieza por https://")

BUCKET = "contratos"
MAX_PDF_SIZE = 20 * 1024 * 1024  # 20MB

templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


CARPETA_DOCS = Path("docs")
CARPETA_DOCS.mkdir(exist_ok=True)


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
ALLOWED_ACTIONS = {"upload", "delete", "restore", "purge", "config_update", "download", "alert_sent"}
ALLOWED_ENTITY_TYPES = {"contratos", "contratos_papelera", "config"}


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
            "stats": {"total": 0, "proximos": 0, "vencidos": 0, "sin_fecha": 0},
            "todos": [],
            "ultimos": [],
            "vencen_30": [],
            "vencen_7": [],
            "vencidos_list": [],
            "sin_fecha_list": [],
            "miembros": [],
            "grafico_labels": [],
            "grafico_values": []
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
            "fecha_fin": fin.isoformat() if fin else None,
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

    # --- KPIs ---
    stats = {
        "total": len(todos),
        "proximos": len(vencen_30),
        "vencidos": len(vencidos_list),
        "sin_fecha": len(sin_fecha_list),
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
            supabase.storage.from_(BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={"content-type": file.content_type or "application/pdf"}
            )
        except Exception:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            storage_path = f"{empresa_slug}/{user_slug}/{ts}_{fname}"
            supabase.storage.from_(BUCKET).upload(
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
            "creado_en": datetime.utcnow().isoformat()
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


from fastapi.responses import JSONResponse


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
            supabase_service.storage.from_(BUCKET).remove([storage_path])
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



# -----------------------------
# Email
# -----------------------------
def enviar_email(destino, asunto, mensaje):
    """
    IMPORTANTE: no pongas credenciales hardcodeadas aquí.
    Usa variables de entorno:
      - SMTP_USER
      - SMTP_APP_PASS
    """
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_APP_PASS", "")
    if not smtp_user or not smtp_pass:
        raise RuntimeError("Faltan SMTP_USER o SMTP_APP_PASS en variables de entorno.")

    yag = yagmail.SMTP(smtp_user, smtp_pass)
    yag.send(destino, asunto, mensaje)


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


from datetime import datetime, timedelta
from fastapi import Header, HTTPException
import os

@app.post("/jobs/enviar_alertas_diarias")
def job_enviar_alertas_diarias(x_cron_secret: str = Header(None)):
    if x_cron_secret != os.environ.get("CRON_SECRET"):
        raise HTTPException(status_code=403, detail="Forbidden")

    if supabase_service is None:
        raise HTTPException(status_code=500, detail="Supabase service no disponible")

    hoy = datetime.utcnow().date()
    limite = hoy + timedelta(days=30)

    empresas = supabase_service.table("empresas").select("id,nombre").execute().data or []

    # ====== contadores globales ======
    empresas_total = len(empresas)
    empresas_con_admins = 0
    empresas_con_destinos = 0
    empresas_con_contratos = 0
    empresas_envio_ok = 0
    total_contratos_encontrados = 0

    # ====== log GLOBAL SIEMPRE (job_run) ======
    try:
        supabase_service.table("audit_log").insert({
            "empresa_id": None,  # global (sin empresa)
            "actor_username": "system",
            "actor_auth_id": None,
            "action": "job_run",
            "entity_type": "cron",
            "entity_id": "enviar_alertas_diarias",
            "metadata": {
                "dias": 30,
                "empresas_total": empresas_total,
                "fecha_hoy": hoy.isoformat(),
                "fecha_limite": limite.isoformat()
            }
        }).execute()
    except Exception as e:
        logger.warning("❌ No se pudo insertar job_run en audit_log: %s", str(e)[:200])

    # ====== loop empresas ======
    for emp in empresas:
        empresa_id = emp.get("id")
        if not empresa_id:
            continue

        admins = (
            supabase_service.table("usuarios_app")
            .select("username,email_alertas")
            .eq("empresa_id", empresa_id)
            .eq("rol", "admin")
            .execute()
            .data
        ) or []

        if admins:
            empresas_con_admins += 1

        destinos = [a.get("email_alertas", "").strip() for a in admins if (a.get("email_alertas") or "").strip()]
        destinos = list(dict.fromkeys(destinos))

        if destinos:
            empresas_con_destinos += 1
        else:
            continue

        contratos = (
            supabase_service.table("contratos")
            .select("id,archivo_pdf,tipo,fecha_fin,owner,storage_path")
            .eq("empresa_id", empresa_id)
            .gte("fecha_fin", hoy.isoformat())
            .lte("fecha_fin", limite.isoformat())
            .order("fecha_fin", desc=False)
            .limit(500)
            .execute()
            .data
        ) or []

        if contratos:
            empresas_con_contratos += 1
            total_contratos_encontrados += len(contratos)
        else:
            continue

        lineas = [
            f"- {c.get('archivo_pdf','')} · {c.get('tipo','otro')} · vence {str(c.get('fecha_fin'))[:10]} · responsable {c.get('owner','')}"
            for c in contratos
        ]

        asunto = "Contralys · Alertas de vencimiento (≤ 30 días)"
        cuerpo = "Contratos próximos a vencer:\n\n" + "\n".join(lineas) + "\n\n— Contralys"

        ok_envio = False
        try:
            for destino in destinos:
                enviar_email(destino, asunto, cuerpo)
            ok_envio = True
        except Exception as ex:
            logger.warning("Fallo enviando alertas empresa=%s error=%s", empresa_id, str(ex)[:160])

        if not ok_envio:
            continue

        # log por-empresa (alert_sent)
        try:
            supabase_service.table("audit_log").insert({
                "empresa_id": empresa_id,
                "actor_username": "system",
                "actor_auth_id": None,
                "action": "alert_sent",
                "entity_type": "contratos",
                "entity_id": None,
                "metadata": {"dias": 30, "cantidad": len(contratos), "destinos": destinos}
            }).execute()
        except Exception as e:
            logger.warning("❌ No se pudo insertar alert_sent en audit_log: %s", str(e)[:200])

        empresas_envio_ok += 1

    # ====== update final: otro job_run resumen (opcional pero útil) ======
    try:
        supabase_service.table("audit_log").insert({
            "empresa_id": None,
            "actor_username": "system",
            "actor_auth_id": None,
            "action": "job_run",
            "entity_type": "cron",
            "entity_id": "enviar_alertas_diarias_result",
            "metadata": {
                "dias": 30,
                "empresas_total": empresas_total,
                "empresas_con_admins": empresas_con_admins,
                "empresas_con_destinos": empresas_con_destinos,
                "empresas_con_contratos": empresas_con_contratos,
                "empresas_envio_ok": empresas_envio_ok,
                "total_contratos_encontrados": total_contratos_encontrados
            }
        }).execute()
    except Exception as e:
        logger.warning("❌ No se pudo insertar job_run_result en audit_log: %s", str(e)[:200])

    return {
        "ok": True,
        "dias": 30,
        "empresas_total": empresas_total,
        "empresas_envio_ok": empresas_envio_ok,
        "empresas_con_contratos": empresas_con_contratos,
        "total_contratos_encontrados": total_contratos_encontrados
    }

@app.get("/debug_job_alertas")
def debug_job_alertas():
    if supabase_service is None:
        return {"ok": False, "error": "no supabase_service"}

    hoy = datetime.utcnow().date()
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

