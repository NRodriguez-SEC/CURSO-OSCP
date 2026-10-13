import subprocess
import xml.etree.ElementTree as ET
import requests
from colorama import Fore

def run_nmap(target):
    """Ejecuta Nmap y parsea la salida XML."""
    print(f"{Fore.YELLOW}[+] Escaneando puertos con Nmap...")
    try:
        # -F: Fast scan (top 100 puertos), -sV: Detección de versiones, -oX -: Salida XML a stdout
        result = subprocess.run(
            ['nmap', '-F', '-sV', '-oX', '-', target],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {"error": "Nmap falló", "detalle": result.stderr}

        # Parsear el XML
        root = ET.fromstring(result.stdout)
        puertos_abiertos = []
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                estado = port.find('state').get('state')
                if estado == 'open':
                    servicio = port.find('service')
                    puertos_abiertos.append({
                        "puerto": port.get('portid'),
                        "protocolo": port.get('protocol'),
                        "servicio": servicio.get('name') if servicio is not None else 'desconocido',
                        "version": servicio.get('version') if servicio is not None else ''
                    })
        return {"puertos_abiertos": puertos_abiertos}
    except subprocess.TimeoutExpired:
        return {"error": "Nmap tardó demasiado"}
    except Exception as e:
        return {"error": str(e)}

def run_directory_scan(target):
    """Búsqueda básica de directorios comunes usando requests."""
    print(f"{Fore.YELLOW}[+] Buscando directorios comunes...")
    # Lista pequeña de directorios comunes
    wordlist = ['admin', 'login', 'backup', 'config', 'robots.txt', 'sitemap.xml', '.git', 'wp-admin']
    encontrados = []
    base_url = target if target.startswith('http') else f'http://{target}'
    
    for path in wordlist:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                encontrados.append({
                    "path": f"/{path}",
                    "status_code": r.status_code,
                    "tamano": len(r.content)
                })
                print(f"{Fore.GREEN}    - Encontrado: /{path} ({r.status_code})")
        except requests.RequestException:
            pass
    return {"directorios_encontrados": encontrados}

def run(target):
    """Ejecuta todos los módulos activos."""
    print(f"\n{Fore.MAGENTA}[*] Iniciando análisis activo para: {target}")
    
    resultados = {
        "nmap": run_nmap(target),
        "directorios": run_directory_scan(target)
    }
    
    print(f"{Fore.MAGENTA}[*] Análisis activo completado.\n")
    return resultados
