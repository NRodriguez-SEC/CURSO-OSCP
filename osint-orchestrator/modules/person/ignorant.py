"""
ignorant.py - Comprueba si un teléfono está registrado en Instagram, Amazon y Snapchat.
Es el equivalente de Holehe, pero para números de teléfono (mismo autor, megadose).

ignorant pide el prefijo y el número por separado (ej. 'ignorant 34 600123456'),
así que usamos phonenumbers para separarlos del número que recibe la herramienta.
"""
import subprocess
import shutil
import os
import sys
import re
import phonenumbers
from colorama import Fore


def run(telefono):
    """Devuelve los sitios donde el teléfono está registrado según ignorant."""
    print(f"{Fore.YELLOW}[+] Comprobando cuentas del teléfono con ignorant...")

    # 1) Separar prefijo internacional y número nacional
    try:
        region = None if str(telefono).strip().startswith("+") else "ES"
        num = phonenumbers.parse(telefono, region)
    except Exception as e:
        return {"error": f"No se pudo parsear el número: {e}", "sitios": []}

    prefijo = str(num.country_code)
    nacional = str(num.national_number)

    # 2) Localizar el binario (igual que holehe)
    binario = shutil.which("ignorant")
    if not binario:
        venv_bin = os.path.join(os.path.dirname(sys.executable), "ignorant")
        binario = venv_bin if os.path.exists(venv_bin) else None
    if not binario:
        return {"error": "ignorant no está instalado (pip install ignorant)", "sitios": []}

    # 3) Ejecutar. --no-color para una salida limpia; si no lo soporta, se reintenta sin él.
    try:
        result = subprocess.run([binario, prefijo, nacional, "--no-color"],
                                capture_output=True, text=True, timeout=120)
        if result.returncode != 0 and "no-color" in (result.stderr or "").lower():
            result = subprocess.run([binario, prefijo, nacional],
                                    capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "ignorant tardó demasiado", "sitios": []}
    except Exception as e:
        return {"error": str(e), "sitios": []}

    sitios = _parsear_salida(result.stdout or "")

    if sitios:
        print(f"{Fore.GREEN}    - Registrado en {len(sitios)} sitios.")
    else:
        print(f"{Fore.YELLOW}    - Sin registros confirmados.")

    return {"telefono": telefono, "prefijo": prefijo, "sitios": sitios, "fuente": "ignorant"}


def _parsear_salida(texto):
    """Extrae los sitios de las líneas '[+]' (registrado), como en Holehe."""
    sitios = []
    vistos = set()
    # Quita posibles códigos de color ANSI que ensucien la línea
    limpio = re.sub(r"\x1b\[[0-9;]*m", "", texto)

    for linea in limpio.split("\n"):
        linea = linea.strip()
        # Solo [+] (cuenta encontrada). [-] no usado y [x] rate limit se ignoran.
        if linea.startswith("[+]"):
            resto = linea[3:].strip()
            sitio = resto.split()[0] if resto else ""
            # El "." descarta la línea de leyenda ("[+] Phone number used, ...")
            # y deja solo dominios reales como "instagram.com".
            if sitio and "." in sitio and sitio not in vistos:
                vistos.add(sitio)
                sitios.append({"sitio": sitio, "registrado": True})

    return sitios
