"""
twilio_lookup.py - Operador ACTUAL del teléfono vía Twilio Lookup v2.

A diferencia de phonenumbers (que da el operador del rango asignado
originalmente), Twilio consulta la red en tiempo real, así que su operador
SÍ refleja la portabilidad: muestra el operador real actual del número.

OPCIONAL y de pago. Se activa con las variables de entorno:
    export TWILIO_ACCOUNT_SID="ACxxxxxxxx"
    export TWILIO_AUTH_TOKEN="xxxxxxxx"
Si no están definidas, el módulo no hace nada y la herramienta sigue
funcionando con phonenumbers (gratis).
"""
import os
import requests
import phonenumbers
from colorama import Fore

URL = "https://lookups.twilio.com/v2/PhoneNumbers/{}"


def run(telefono):
    sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    token = os.getenv("TWILIO_AUTH_TOKEN", "")

    # No configurado: no es un error, simplemente no se usa.
    if not sid or not token:
        return {
            "disponible": False,
            "nota": "Twilio no configurado (define TWILIO_ACCOUNT_SID y TWILIO_AUTH_TOKEN para el operador actual).",
        }

    print(f"{Fore.YELLOW}[+] Consultando operador actual en Twilio Lookup...")

    # Twilio quiere el número en formato E164 (+34...)
    try:
        region = None if str(telefono).strip().startswith("+") else "ES"
        num = phonenumbers.parse(telefono, region)
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    except Exception as e:
        return {"disponible": True, "error": f"No se pudo formatear el número: {e}"}

    try:
        r = requests.get(
            URL.format(e164),
            params={"Fields": "line_type_intelligence"},
            auth=(sid, token),
            timeout=15,
        )
    except requests.RequestException as e:
        return {"disponible": True, "error": str(e)}

    if r.status_code == 401:
        return {"disponible": True, "error": "Credenciales de Twilio inválidas (401)."}
    if r.status_code == 404:
        return {"disponible": True, "error": "Número no encontrado en Twilio (404)."}
    if r.status_code != 200:
        return {"disponible": True, "error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
    except ValueError:
        return {"disponible": True, "error": "Respuesta de Twilio no válida."}

    lti = data.get("line_type_intelligence") or {}
    if lti.get("error_code"):
        return {"disponible": True, "error": f"Twilio error_code {lti['error_code']}"}

    resultado = {
        "disponible": True,
        "operador_actual": lti.get("carrier_name") or "Desconocido",
        "tipo_linea": lti.get("type") or "Desconocido",
        "mcc": lti.get("mobile_country_code"),
        "mnc": lti.get("mobile_network_code"),
        "fuente": "Twilio Lookup v2",
    }
    print(f"{Fore.GREEN}    - Operador actual (Twilio): {resultado['operador_actual']} ({resultado['tipo_linea']})")
    return resultado
