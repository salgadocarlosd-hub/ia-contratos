import os
import requests

# Pon aquí tu gmail y APP PASSWORD (mejor si lo configuras como variables del sistema)
# os.environ["SMTP_USER"] = "tu_gmail@gmail.com"
# os.environ["SMTP_APP_PASS"] = "tu_app_password"

URL = "http://127.0.0.1:8000/enviar_alertas/?dias=30"

r = requests.get(URL, timeout=30)
print(r.status_code, r.text)
