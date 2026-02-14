from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from pathlib import Path
from pypdf import PdfReader

import pytesseract
from pdf2image import convert_from_path

import re, json, os
from datetime import datetime, timedelta
from dateutil import parser

from passlib.context import CryptContext
import yagmail

import os
from io import BytesIO
from supabase import create_client


# -----------------------------
# App + templates + session
# -----------------------------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="cambia-esto-por-una-clave-larga")

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

templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


CARPETA_DOCS = Path("docs")
CARPETA_DOCS.mkdir(exist_ok=True)

USUARIOS = Path("usuarios.json")
CONFIGS = Path("configs.json")
REGISTRO = Path("registro_contratos.json")


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
def cargar_registro():
    if REGISTRO.exists():
        return json.loads(REGISTRO.read_text(encoding="utf-8"))
    return []


def guardar_registro(data):
    REGISTRO.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


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
    mensaje = "Contrato subido y procesado ✅" if ok == "1" else None

    empresa = get_empresa(user) or "Mi empresa"

    if supabase is None:
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "contratos": [],
            "user": user,
            "mensaje": "⚠️ Supabase no está configurado en Render (Environment)."
        })

    # Leer contratos de la empresa desde Supabase
    res = (
        supabase
        .table("contratos")
        .select("archivo_pdf,fecha_fin,tipo,creado_en,owner")
        .eq("empresa", empresa)
        .execute()
    )
    items = res.data or []

    hoy = datetime.now().date()
    limite = hoy + timedelta(days=30)

    contratos = []
    for it in items:
        fecha_fin = it.get("fecha_fin")
        if not fecha_fin:
            continue

        try:
            # Supabase suele devolver "YYYY-MM-DD"
            fin_date = datetime.fromisoformat(str(fecha_fin)).date()
        except Exception:
            continue

        if fin_date <= limite:
            contratos.append({
                "archivo_pdf": it.get("archivo_pdf"),
                "tipo": it.get("tipo", "otro"),
                "vence_el": str(fecha_fin),
                "dias_restantes": (fin_date - hoy).days
            })

    contratos.sort(key=lambda x: x["vence_el"])

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "contratos": contratos,
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
        return templates.TemplateResponse("respuesta.html", {
            "request": request,
            "pregunta": "Error de configuración",
            "respuesta": "Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en Render (Environment)."
        })

    empresa = get_empresa(user) or "Mi empresa"
    empresa_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", empresa).strip("_")
    user_slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", user).strip("_")

    # Leer el PDF UNA vez (bytes)
    pdf_bytes = await file.read()

    # 1) Subir a Supabase Storage
    storage_path = f"{empresa_slug}/{user_slug}/{file.filename}"
    supabase.storage.from_(BUCKET).upload(
        path=storage_path,
        file=pdf_bytes,
        file_options={"content-type": file.content_type or "application/pdf"}
    )

    # 2) Extraer texto (sin disco)
    texto = extraer_texto_pdf_bytes(pdf_bytes)

    # 3) Sacar datos
    fecha_fin = extraer_fecha_fin(texto)
    tipo_contrato = clasificar_contrato(texto)

    # 4) Guardar en Postgres (tabla contratos)
    supabase.table("contratos").insert({
        "empresa": empresa,
        "owner": user,
        "archivo_pdf": file.filename,
        "storage_path": storage_path,
        "fecha_fin": fecha_fin,
        "tipo": tipo_contrato
    }).execute()

    return RedirectResponse(url="/?ok=1", status_code=303)



# -----------------------------
# Consultas
# -----------------------------
@app.get("/vencen_en/")
def vencen_en(dias: int = 30, owner: str | None = None):
    limite = (datetime.now().date() + timedelta(days=dias))

    registro = cargar_registro()
    resultados = []

    for item in registro:
        if owner and item.get("owner") != owner:
            continue

        fechas = item.get("fechas_detectadas", [])
        if not fechas:
            continue

        posible_fin = item.get("fecha_fin_detectada") or max(fechas)

        try:
            fin_date = datetime.fromisoformat(posible_fin).date()
        except Exception:
            continue

        if fin_date <= limite:
            resultados.append({
                "owner": item.get("owner"),
                "archivo_pdf": item.get("archivo_pdf"),
                "posible_vencimiento": posible_fin,
                "fechas_detectadas": fechas
            })

    resultados.sort(key=lambda x: x["posible_vencimiento"])

    return {
        "hoy": datetime.now().date().isoformat(),
        "limite": limite.isoformat(),
        "dias": dias,
        "resultados": resultados
    }


@app.get("/alertas_vencimiento/")
def alertas_vencimiento(dias: int = 30, owner: str | None = None):
    limite = (datetime.now().date() + timedelta(days=dias))

    registro = cargar_registro()
    alertas = []

    for item in registro:
        if owner and item.get("owner") != owner:
            continue

        fecha_fin = item.get("fecha_fin_detectada")
        if not fecha_fin:
            continue

        try:
            fin_date = datetime.fromisoformat(fecha_fin).date()
        except:
            continue

        if fin_date <= limite:
            alertas.append({
                "owner": item.get("owner"),
                "archivo_pdf": item.get("archivo_pdf"),
                "vence_el": fecha_fin,
                "dias_restantes": (fin_date - datetime.now().date()).days
            })

    alertas.sort(key=lambda x: x["vence_el"])

    return {
        "alertas": alertas,
        "limite": limite.isoformat()
    }


@app.post("/preguntar_contratos/")
async def preguntar_contratos(request: Request, pregunta: str = Form(...)):
    user = usuario_actual(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    registro = cargar_registro()
    contratos_usuario = [c for c in registro if c.get("owner") == user]

    pregunta_l = pregunta.lower()
    hoy = datetime.now().date()

    # detectar "en X días"
    dias = None
    m = re.search(r"(\d+)\s*d[ií]as", pregunta_l)
    if m:
        dias = int(m.group(1))

    resultados = []

    for c in contratos_usuario:
        fecha = c.get("fecha_fin_detectada")
        if not fecha:
            continue

        fin = datetime.fromisoformat(fecha).date()

        incluir = True

        if dias:
            incluir = fin <= (hoy + timedelta(days=dias))

        if "alquiler" in pregunta_l:
            incluir = incluir and c.get("tipo") == "alquiler"

        if incluir:
            resultados.append(
                f"{c.get('archivo_pdf')} ({c.get('tipo')}) vence el {fecha}"
            )

    if not resultados:
        respuesta = "No encontré coincidencias."
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
def enviar_alertas(dias: int = 30):
    registro = cargar_registro()

    por_usuario = {}
    for item in registro:
        owner = item.get("owner")
        if owner:
            por_usuario.setdefault(owner, []).append(item)

    enviados = []

    for owner, items in por_usuario.items():
        destino = get_email_alertas(owner)
        if not destino:
            continue

        alertas = []
        limite = (datetime.now().date() + timedelta(days=dias))

        for item in items:
            fecha_fin = item.get("fecha_fin_detectada")
            if not fecha_fin:
                continue
            try:
                fin_date = datetime.fromisoformat(fecha_fin).date()
            except:
                continue
            if fin_date <= limite:
                alertas.append((item.get("archivo_pdf"), fecha_fin, (fin_date - datetime.now().date()).days))

        if not alertas:
            continue

        asunto = f"Alertas de contratos (<= {dias} días)"
        cuerpo = "Contratos próximos a vencer:\n\n" + "\n".join(
            [f"- {a[0]} vence el {a[1]} (quedan {a[2]} días)" for a in alertas]
        )

        enviar_email(destino, asunto, cuerpo)
        enviados.append({"owner": owner, "destino": destino, "num_alertas": len(alertas)})

    return {"enviados": enviados}
