#!/usr/bin/env python3
"""Analiza las cabeceras de seguridad de la respuesta de un sitio web.
Uso: python3 cabeceras_seguridad.py https://example.com
"""
import sys
import urllib.error
import urllib.request
import http.client

CABECERAS = {
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS)",
    "Content-Security-Policy": "Mitiga XSS e inyección de contenido",
    "X-Frame-Options": "Protege contra clickjacking",
    "X-Content-Type-Options": "Evita MIME sniffing (debe ser 'nosniff')",
    "Referrer-Policy": "Controla la información del Referer",
    "Permissions-Policy": "Restringe APIs del navegador (cámara, geolocalización...)",
    "Cross-Origin-Opener-Policy": "Aislamiento de contexto de navegación",
    "Cross-Origin-Resource-Policy": "Controla quién puede cargar el recurso",
}
CABECERAS_INFO = ["Server", "X-Powered-By", "X-AspNet-Version"]  # filtran tecnología


def analizar_extra(url):
    print("\n== Análisis Extra (OSCP) ==")
    # 1. Análisis de Cookies
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        cookies = resp.headers.get_all("Set-Cookie")
        if cookies:
            for cookie in cookies:
                flags = []
                if "HttpOnly" in cookie: flags.append("HttpOnly")
                if "Secure" in cookie: flags.append("Secure")
                if "SameSite" in cookie: flags.append("SameSite")
                print(f"[COOKIE] {cookie[:50]}... -> Flags: {', '.join(flags) if flags else 'NINGUNA'}")
        else:
            print("[COOKIE] No se establecieron cookies.")
    except Exception as e:
        print(f"Error en cookies: {e}")

    # 2. Métodos HTTP permitidos
    try:
        conn = http.client.HTTPConnection(url.split("//")[1].split("/")[0])
        conn.request("OPTIONS", "/")
        res = conn.getresponse()
        print(f"[MÉTODOS] Allowed: {res.getheader('Allow', 'No especificado')}")
    except Exception as e:
        print(f"Error en métodos HTTP: {e}")

    # 3. CORS
    try:
        req = urllib.request.Request(url, headers={"Origin": "https://evil.com"})
        resp = urllib.request.urlopen(req, timeout=10)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        if acao == "*" or acao == "https://evil.com":
            print(f"[VULN] CORS mal configurado: {acao} (Permite cualquier origen)")
        else:
            print(f"[CORS] Access-Control-Allow-Origin: {acao}")
    except Exception as e:
        print(f"Error en CORS: {e}")

def analizar(url):
# Añadir a cabeceras_seguridad.py dentro de analizar()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "AnalizadorCabeceras/1.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as e:
        resp = e  # también contiene cabeceras
    except Exception as e:
        print("Error de conexión:", e)
        sys.exit(1)

    cab = {k.lower(): v for k, v in resp.headers.items()}
    print(f"\nURL: {url}   Estado: {resp.status if hasattr(resp, 'status') else resp.code}\n")

    presentes = 0
    print("== Cabeceras de seguridad ==")
    for nombre, desc in CABECERAS.items():
        valor = cab.get(nombre.lower())
        if valor:
            presentes += 1
            print(f"[OK]      {nombre}: {valor[:80]}")
        else:
            print(f"[FALTA]   {nombre}  -> {desc}")

    print("\n== Cabeceras que revelan información ==")
    for nombre in CABECERAS_INFO:
        if nombre.lower() in cab:
            print(f"[AVISO]   {nombre}: {cab[nombre.lower()]}")

    print(f"\nPuntuación: {presentes}/{len(CABECERAS)} cabeceras de seguridad presentes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    analizar(sys.argv[1])
