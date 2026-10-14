#!/usr/bin/env python3
"""Enumeración pasiva y activa de un dominio.
USO SOLO EN SISTEMAS PROPIOS O CON AUTORIZACIÓN (p. ej. scanme.nmap.org, laboratorio de clase).

Ejemplos:
  python3 enumeracion.py scanme.nmap.org --pasiva
  python3 enumeracion.py scanme.nmap.org --activa
  python3 enumeracion.py scanme.nmap.org --pasiva --activa
"""
import argparse
import json
import socket
import time
import urllib.error
import urllib.request
import re
from concurrent.futures import ThreadPoolExecutor

PUERTOS_COMUNES = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                   3306, 3389, 5432, 8000, 8080, 8443]
SUBDOMINIOS_COMUNES = ["www", "mail", "ftp", "dev", "test", "admin", "api",
                       "blog", "vpn", "ns1", "ns2", "staging", "portal",
                       "scanme", "svn", "nmap", "insecure", "seclists"]


def dominio_base(dominio):
    """scanme.nmap.org -> nmap.org (simplificación: últimas dos etiquetas)."""
    return ".".join(dominio.split(".")[-2:])


# ---------------------------- PASIVA ----------------------------
# No se envía tráfico al objetivo: se usan fuentes públicas (DNS, WHOIS, CT logs).

def resolver_dns(dominio):
    try:
        nombre, alias, ips = socket.gethostbyname_ex(dominio)
        return {"nombre": nombre, "alias": alias, "ips": ips}
    except socket.gaierror as e:
        return {"error": str(e)}


def _consulta_whois(servidor, consulta):
    with socket.create_connection((servidor, 43), timeout=10) as s:
        s.sendall((consulta + "\r\n").encode())
        datos = b""
        while True:
            trozo = s.recv(4096)
            if not trozo:
                break
            datos += trozo
    return datos.decode(errors="ignore")


def whois(dominio):
    base = dominio_base(dominio)  # el WHOIS solo entiende el dominio registrado
    try:
        resp = _consulta_whois("whois.iana.org", base)
        for linea in resp.splitlines():
            if linea.lower().startswith("refer:"):
                return _consulta_whois(linea.split(":", 1)[1].strip(), base)
        return resp
    except OSError as e:
        return f"Error WHOIS: {e}"


def subdominios_crtsh(dominio, intentos=3):
    """Subdominios a partir de los logs de Certificate Transparency (crt.sh)."""
    base = dominio_base(dominio)
    url = f"https://crt.sh/?q=%25.{base}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    for intento in range(1, intentos + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                datos = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code == 429 and intento < intentos:
                espera = 10 * intento
                print(f" (crt.sh limita las peticiones, reintento en {espera}s...)")
                time.sleep(espera)
                continue
            return [f"Error crt.sh: HTTP {e.code} (espera un par de minutos y repite)"]
        except Exception as e:
            return [f"Error crt.sh: {e}"]
    subs = set()
    for entrada in datos:
        for nombre in entrada.get("name_value", "").split("\n"):
            subs.add(nombre.strip().lower().lstrip("*."))
    return sorted(subs)


def enumeracion_pasiva(dominio):
    print(f"\n=== ENUMERACIÓN PASIVA: {dominio} ===")
    print("\n[DNS]")
    print(json.dumps(resolver_dns(dominio), indent=2, ensure_ascii=False))
    print(f"\n[WHOIS de {dominio_base(dominio)}]")
    print(whois(dominio)[:2000])
    print(f"\n[Subdominios de {dominio_base(dominio)} vía crt.sh]")
    for s in subdominios_crtsh(dominio):
        print(" -", s)


# ---------------------------- ACTIVA ----------------------------
# Se envían paquetes al objetivo: requiere autorización.

def obtener_titulo_web(ip, puerto):
    try:
        conn = http.client.HTTPConnection(ip, puerto, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        html = res.read(1024).decode(errors="ignore")
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        return match.group(1) if match else "Sin título"
    except:
        return "No accesible"

def escanear_puerto(ip, puerto, timeout=4):
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            banner = ""
            try:
                if puerto in (80, 8000, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                lineas = s.recv(200).decode(errors="ignore").strip().splitlines()
                banner = lineas[0] if lineas else ""
            except OSError:
                pass
            return puerto, banner
    except OSError:
        return None


def escaneo_puertos(ip):
    print("\n[Escaneo de puertos TCP + banner grabbing]")
    with ThreadPoolExecutor(max_workers=50) as ex:
        resultados = list(ex.map(lambda p: escanear_puerto(ip, p), PUERTOS_COMUNES))
    abiertos = [r for r in resultados if r]
    if not abiertos:
        print(" (ningún puerto abierto de la lista)")
    for puerto, banner in abiertos:
        try:
            servicio = socket.getservbyport(puerto)
        except OSError:
            servicio = "desconocido"
        print(f" - {puerto}/tcp abierto ({servicio}) {banner}")


def fuerza_bruta_subdominios(dominio):
    base = dominio_base(dominio)
    print(f"\n[Fuerza bruta de subdominios de {base}]")

    def probar(sub):
        nombre = f"{sub}.{base}"
        try:
            return nombre, socket.gethostbyname(nombre)
        except socket.gaierror:
            return None

    # Detección de DNS comodín (wildcard): un nombre aleatorio que no debería existir
    aleatorio = f"zz-no-existe-{int(time.time())}.{base}"
    try:
        ip_comodin = socket.gethostbyname(aleatorio)
        print(f" [!] DNS comodín detectado: cualquier subdominio resuelve a {ip_comodin}")
        print("     Se descartan los resultados con esa IP (falsos positivos).")
    except socket.gaierror:
        ip_comodin = None

    encontrados = 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(probar, SUBDOMINIOS_COMUNES):
            if r and r[1] != ip_comodin:
                encontrados += 1
                print(f" - {r[0]} -> {r[1]}")
    if not encontrados:
        print(" (ningún subdominio válido de la lista)")


def enumeracion_activa(dominio):
    print(f"\n=== ENUMERACIÓN ACTIVA: {dominio} ===")
    try:
        ip = socket.gethostbyname(dominio)
    except socket.gaierror as e:
        print("No se pudo resolver el dominio:", e)
        return
    print("IP objetivo:", ip)
    escaneo_puertos(ip)
    fuerza_bruta_subdominios(dominio)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Enumeración pasiva y activa")
    ap.add_argument("dominio")
    ap.add_argument("--pasiva", action="store_true")
    ap.add_argument("--activa", action="store_true")
    args = ap.parse_args()
    if not (args.pasiva or args.activa):
        args.pasiva = args.activa = True
    if args.pasiva:
        enumeracion_pasiva(args.dominio)
    if args.activa:
        enumeracion_activa(args.dominio)
# Añadir a enumeracion.py
def guardar_reporte(dominio, resultados):
    with open(f"reporte_{dominio}.md", "w", encoding="utf-8") as f:
        f.write(f"# Reporte de Reconocimiento: {dominio}\n\n")
        f.write("## Puertos Abiertos\n")
        f.write("| Puerto | Servicio | Banner |\n|---|---|---|\n")
        for puerto, banner in resultados:
            f.write(f"| {puerto} | {socket.getservbyport(puerto, 'tcp')} | {banner[:50]} |\n")
        f.write("\n## Subdominios Encontrados\n")
        # ... añadir lógica para subdominios
