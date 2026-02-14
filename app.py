from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from pathlib import Path
from pypdf import PdfReader

import re, json, os
from urllib.parse import quote
import logging
from datetime import datetime, timedelta
from dateutil import parser

from passlib.context import CryptContext
import yagmail

from io import BytesIO
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()


# -----------------------------
# App + templates + session
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("contractai")

app = FastAPI()
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=True,       # solo cookies por HTTPS
    same_site="lax"        # protección CSRF básica
)

SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").strip()
SUPABASE_SERVICE_ROLE_KEY = (os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()

supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
else:
    print("⚠️ SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY no están configuradas en el entorno.")

if SUPABASE_URL and not SUPABASE_URL.startswith("https://"):
    print("⚠️ SUPABASE_URL no empieza por https://")

BUCKET = "contratos"
MAX_PDF_SIZE = 20 * 1024 * 1024  # 20MB

templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


CARPETA_DOCS = Path("docs")
CARPETA_DOCS.mkdir(exist_ok=True)

USUARIOS = Path("usuarios.json")
CONFIGS = Path("configs.json")


# -----------------------------
# Helpers: auth
# -----------------------------
def usuario_actual(request: Request):
    return request.session.get("user")


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

def cargar_usuarios():
    if USUARIOS.exists():
        return json.loads(USUARIOS.read_text(encoding="utf-8"))
    return []


def guardar_usuarios(data):
    USUARIOS.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def crear_usuario(username: str, password: str):
    usuarios = cargar_usuarios()
    if any(u["username"] == username for u in usuarios):
        return False

    password = normalizar_password(password)

    usuarios.append({
        "username": username,
        "password_hash": pwd_context.hash(password)
    })
    guardar_usuarios(usuarios)
    return True


def validar_usuario(username: str, password: str):
    usuarios = cargar_usuarios()
    u = next((x for x in usuarios if x["username"] == username), None)
    if not u:
        return False

    password = normalizar_password(password)
    return pwd_context.verify(password, u["password_hash"])


# -----------------------------
# Helpers: configs (email alertas)
# -----------------------------
def cargar_configs():
    if CONFIGS.exists():
        return json.loads(CONFIGS.read_text(encoding="utf-8"))
    return {}


def guardar_configs(data):
    CONFIGS.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get_email_alertas(username: str):
    cfg = cargar_configs()
    return cfg.get(username, {}).get("email_alertas")


def set_email_alertas(username: str, email: str):
    cfg = cargar_configs()
    cfg.setdefault(username, {})["email_alertas"] = email.strip()
    guardar_configs(cfg)


def get_empresa(username: str):
    cfg = cargar_configs()
    return cfg.get(username, {}).get("empresa", "")


def set_empresa(username: str, empresa: str):
    cfg = cargar_configs()
    cfg.setdefault(username, {})["empresa"] = empresa.strip()
    guardar_configs(cfg)


import secrets
import string


def get_empresa_codigo(username: str):
    cfg = cargar_configs()
    return cfg.get(username, {}).get("empresa_codigo", "")


def set_empresa_codigo(username: str, codigo: str):
    cfg = cargar_configs()
    cfg.setdefault(username, {})["empresa_codigo"] = codigo.strip().upper()
    guardar_configs(cfg)


def generar_codigo_empresa():
    alfabeto = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alfabeto) for _ in range(6))


def buscar_empresa_por_codigo(codigo: str):
    cfg = cargar_configs()
    codigo = (codigo or "").strip().upper()
    for user, data in cfg.items():
        if data.get("empresa_codigo", "").upper() == codigo:
            return data.get("empresa")
    return None

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


def obtener_contratos_supabase(empresa: str, owner: str | None = None, limit: int = 200):
    """
    Devuelve contratos desde Supabase (tabla contratos) para una empresa.
    Si owner se pasa, filtra por usuario.
    """
    if supabase is None:
        return []

    q = (
        supabase
        .table("contratos")
        .select("archivo_pdf,fecha_fin,tipo,owner,creado_en,storage_path")
        .eq("empresa", empresa)
        .order("creado_en", desc=True)
        .limit(limit)
    )

    if owner:
        q = q.eq("owner", owner)

    res = q.execute()
    return res.data or []


def obtener_alertas_supabase(empresa: str, dias: int = 30, owner: str | None = None, limit: int = 500):
    """
    Devuelve contratos con fecha_fin <= hoy + dias desde Supabase.
    """
    if supabase is None:
        return []

    hoy = datetime.now().date()
    limite = hoy + timedelta(days=dias)

    # Traemos contratos con fecha_fin no nula (filtraremos en Python por seguridad)
    q = (
        supabase
        .table("contratos")
        .select("archivo_pdf,fecha_fin,tipo,owner,creado_en,storage_path")
        .eq("empresa", empresa)
        .order("fecha_fin", desc=False)
        .limit(limit)
    )

    if owner:
        q = q.eq("owner", owner)

    res = q.execute()
    items = res.data or []

    alertas = []
    for it in items:
        fecha = it.get("fecha_fin")
        if not fecha:
            continue
        try:
            fin = datetime.fromisoformat(str(fecha)).date()
        except:
            continue

        if fin <= limite:
            alertas.append({
                "owner": it.get("owner"),
                "archivo_pdf": it.get("archivo_pdf"),
                "tipo": it.get("tipo", "otro"),
                "vence_el": str(fecha),
                "dias_restantes": (fin - hoy).days,
                "storage_path": it.get("storage_path", "")
            })

    alertas.sort(key=lambda x: x["vence_el"])
    return alertas


# -----------------------------
# Auth pages
# -----------------------------
@app.get("/login")
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if validar_usuario(username, password):
        request.session["user"] = username
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Usuario o contraseña incorrectos"})


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
    ok = crear_usuario(username, password)
    if not ok:
        return templates.TemplateResponse(
            "registro.html",
            {"request": request, "error": "Ese usuario ya existe"}
        )

    # iniciar sesión
    request.session["user"] = username

    # unir a empresa si mete código
    empresa_por_codigo = buscar_empresa_por_codigo(codigo_empresa)
    if empresa_por_codigo:
        set_empresa(username, empresa_por_codigo)

    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)



# -----------------------------
# Dashboard
# -----------------------------
@app.get("/")
def dashboard(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    ok = request.query_params.get("ok")
    err = request.query_params.get("err")

    if err:
        mensaje = f"❌ Error: {err}"
    elif ok == "1":
        mensaje = "Contrato subido y procesado ✅"
    else:
        mensaje = None

    empresa = get_empresa(user) or "Mi empresa"

    if supabase is None:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "contratos": [],
            "ultimos": [],
            "user": user,
            "mensaje": "⚠️ Supabase no configurado."
        })

    res = (
        supabase
        .table("contratos")
        .select("archivo_pdf,fecha_fin,tipo,creado_en,owner,storage_path")
        .eq("empresa", empresa)
        .order("creado_en", desc=True)
        .limit(50)
        .execute()
    )

    items = res.data or []

    ultimos = []
    for it in items[:10]:
        ultimos.append({
            "archivo_pdf": it.get("archivo_pdf"),
            "tipo": it.get("tipo", "otro"),
            "fecha_fin": str(it.get("fecha_fin") or ""),
            "owner": it.get("owner", ""),
            "storage_path": it.get("storage_path", "")
        })

    hoy = datetime.now().date()
    limite = hoy + timedelta(days=30)

    contratos = []
    for it in items:
        fecha_fin = it.get("fecha_fin")
        if not fecha_fin:
            continue
        try:
            fin_date = datetime.fromisoformat(str(fecha_fin)).date()
        except Exception:
            continue

        if fin_date <= limite:
            contratos.append({
                "archivo_pdf": it.get("archivo_pdf"),
                "tipo": it.get("tipo", "otro"),
                "vence_el": str(fecha_fin),
                "dias_restantes": (fin_date - hoy).days,
                "storage_path": it.get("storage_path", "")
            })

    contratos.sort(key=lambda x: x["vence_el"])

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "contratos": contratos,
        "ultimos": ultimos,
        "user": user,
        "mensaje": mensaje
    })


# -----------------------------
# Subida PDF -> Supabase (Storage + DB)
# -----------------------------
@app.post("/subir_pdf/")
async def subir_pdf(request: Request, file: UploadFile = File(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase is None:
        return RedirectResponse(url="/?ok=0&err=" + quote("Supabase no configurado"), status_code=303)

    try:
        logger.info("Subida PDF iniciada user=%s file=%s", user, file.filename)

        # Validación: solo PDF
        ct = (file.content_type or "").lower()
        if "pdf" not in ct and not (file.filename or "").lower().endswith(".pdf"):
            return RedirectResponse(url="/?ok=0&err=" + quote("Solo se permiten archivos PDF"), status_code=303)

        empresa = get_empresa(user) or "Mi empresa"

# Evitar duplicado por nombre para este usuario
res_dup = (
    supabase
    .table("contratos")
    .select("id")
    .eq("empresa", empresa)
    .eq("owner", user)
    .eq("archivo_pdf", file.filename)
    .limit(1)
    .execute()
)

if res_dup.data:
    return RedirectResponse(
        url="/?ok=0&err=" + quote("Ya existe un contrato con ese nombre"),
        status_code=303
    )

        empresa_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", empresa).strip("_")
        user_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", user).strip("_")

        # Leer bytes
        pdf_bytes = await file.read()

        if len(pdf_bytes) > MAX_PDF_SIZE:
            return RedirectResponse(
               url="/?ok=0&err=" + quote("El archivo supera el límite de 20MB"),
               status_code=303
            )

        if not pdf_bytes:
            return RedirectResponse(url="/?ok=0&err=" + quote("Archivo vacío"), status_code=303)

        # Ruta en Storage
        storage_path = f"{empresa_slug}/{user_slug}/{file.filename}"

        # Subir a Supabase Storage
        try:
            supabase.storage.from_(BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={"content-type": file.content_type or "application/pdf"}
            )
        except Exception:
            # Si existe o falla, renombrar con timestamp y reintentar
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            storage_path = f"{empresa_slug}/{user_slug}/{ts}_{file.filename}"
            supabase.storage.from_(BUCKET).upload(
                path=storage_path,
                file=pdf_bytes,
                file_options={"content-type": file.content_type or "application/pdf"}
            )

        # Extraer texto
        texto = extraer_texto_pdf_bytes(pdf_bytes)

        # Extraer datos
        fecha_fin = extraer_fecha_fin(texto)
        tipo_contrato = clasificar_contrato(texto)

        # Guardar en Postgres
        supabase.table("contratos").insert({
            "empresa": empresa,
            "owner": user,
            "archivo_pdf": file.filename,
            "storage_path": storage_path,
            "fecha_fin": fecha_fin,
            "tipo": tipo_contrato
        }).execute()

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

    if supabase is None:
        return RedirectResponse(url="/?ok=0&err=" + quote("Supabase no disponible"), status_code=303)

    empresa = get_empresa(user) or "Mi empresa"

    # Seguridad: comprobar que ese storage_path pertenece a este usuario/empresa
    try:
        res = (
            supabase
            .table("contratos")
            .select("storage_path")
            .eq("empresa", empresa)
            .eq("owner", user)
            .eq("storage_path", path)
            .limit(1)
            .execute()
        )
        if not (res.data and len(res.data) > 0):
            return RedirectResponse(url="/?ok=0&err=" + quote("No autorizado"), status_code=303)
    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(str(e)[:120]), status_code=303)

    # Generar URL firmada (10 minutos)
    try:
        signed = supabase.storage.from_(BUCKET).create_signed_url(path, 60 * 10)
        url = signed.get("signedURL") if isinstance(signed, dict) else None
        if not url:
            return RedirectResponse(url="/?ok=0&err=" + quote("No se pudo generar link"), status_code=303)
        return RedirectResponse(url=url, status_code=302)
    except Exception as e:
        return RedirectResponse(url="/?ok=0&err=" + quote(str(e)[:160]), status_code=303)


# -----------------------------
# Consultas
# -----------------------------
@app.get("/vencen_en/")
def vencen_en(request: Request, dias: int = 30):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if supabase is None:
        return {
            "ok": False,
            "error": "Supabase no disponible",
            "resultados": []
        }

    empresa = get_empresa(user) or "Mi empresa"

    # Solo devuelve del usuario actual (seguridad)
    alertas = obtener_alertas_supabase(empresa=empresa, dias=dias, owner=user)

    resultados = []
    for a in alertas:
        resultados.append({
            "archivo_pdf": a["archivo_pdf"],
            "tipo": a.get("tipo", "otro"),
            "vence_el": a["vence_el"],
            "dias_restantes": a["dias_restantes"]
        })

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

    if supabase is None:
        return {"ok": False, "error": "Supabase no disponible", "alertas": []}

    empresa = get_empresa(user) or "Mi empresa"

    alertas = obtener_alertas_supabase(empresa=empresa, dias=dias, owner=user)

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

    if supabase is None:
        return templates.TemplateResponse("respuesta.html", {
            "request": request,
            "pregunta": pregunta,
            "respuesta": "❌ Supabase no está disponible ahora mismo. Inténtalo de nuevo en unos minutos."
        })

    empresa = get_empresa(user) or "Mi empresa"

    # Traer contratos del usuario desde Supabase
    try:
        items = obtener_contratos_supabase(empresa=empresa, owner=user, limit=300)
    except Exception as e:
        return templates.TemplateResponse("respuesta.html", {
            "request": request,
            "pregunta": pregunta,
            "respuesta": f"❌ Error consultando Supabase: {str(e)[:180]}"
        })

    pregunta_l = (pregunta or "").lower()
    hoy = datetime.now().date()

    # Detectar "en X días"
    dias = None
    m = re.search(r"(\d+)\s*d[ií]as", pregunta_l)
    if m:
        try:
            dias = int(m.group(1))
        except:
            dias = None

    # Detectar tipo si el usuario escribe "alquiler", "seguro", etc.
    tipos_validos = ["alquiler", "seguro", "servicios", "laboral", "préstamo", "prestamo", "otro"]
    tipo_filtro = None
    for t in tipos_validos:
        if t in pregunta_l:
            tipo_filtro = "préstamo" if t == "prestamo" else t
            break

    resultados = []

    for it in items:
        fecha = it.get("fecha_fin")
        if not fecha:
            continue

        # fecha_fin suele venir como "YYYY-MM-DD"
        try:
            fin = datetime.fromisoformat(str(fecha)).date()
        except:
            continue

        incluir = True

        if dias is not None:
            incluir = fin <= (hoy + timedelta(days=dias))

        if tipo_filtro:
            incluir = incluir and (it.get("tipo") == tipo_filtro)

        if incluir:
            resultados.append(
                f"{it.get('archivo_pdf')} ({it.get('tipo', 'otro')}) vence el {str(fecha)}"
            )

    if not resultados:
        respuesta = "No encontré coincidencias con esa pregunta."
    else:
        respuesta = "\n".join(resultados)

    return templates.TemplateResponse("respuesta.html", {
        "request": request,
        "pregunta": pregunta,
        "respuesta": respuesta
    })


# -----------------------------
# Config (email por usuario)
# -----------------------------
@app.get("/config")
def config_get(request: Request):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    empresa = get_empresa(user)
    codigo = get_empresa_codigo(user)

    if empresa and not codigo:
        codigo = generar_codigo_empresa()
        set_empresa_codigo(user, codigo)

    return templates.TemplateResponse("config.html", {
        "request": request,
        "empresa": empresa,
        "codigo": codigo,
        "email": get_email_alertas(user),
        "ok": False
    })


@app.post("/config")
def config_post(request: Request, email: str = Form(""), empresa: str = Form("")):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    set_email_alertas(user, email)
    set_empresa(user, empresa)

    codigo = get_empresa_codigo(user)
    if empresa and not codigo:
        codigo = generar_codigo_empresa()
        set_empresa_codigo(user, codigo)

    return templates.TemplateResponse("config.html", {
        "request": request,
        "codigo": get_empresa_codigo(user),
        "email": email,
        "empresa": empresa,
        "ok": True
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

    if supabase is None:
        return {"ok": False, "error": "Supabase no disponible", "enviados": []}

    empresa = get_empresa(user) or "Mi empresa"
    destino = get_email_alertas(user)

    if not destino:
        return {"ok": False, "error": "No tienes email configurado en /config", "enviados": []}

    alertas = obtener_alertas_supabase(empresa=empresa, dias=dias, owner=user)

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

    return {
        "ok": True,
        "enviados": [{"owner": user, "destino": destino, "num_alertas": len(alertas)}]
    }
