import subprocess
import json
import os
import re
from colorama import Fore

# theHarvester incluye en su banner/créditos el dominio y el email de su autor
# (Christian Martorella / edge-security.com). Los filtramos para que no salgan
# como resultados del objetivo.
RUIDO = {"edge-security.com"}


def _sin_ruido_emails(emails):
    return [e for e in emails if e.rsplit("@", 1)[-1].lower() not in RUIDO]


def _sin_ruido_hosts(hosts):
    limpios = []
    for h in hosts:
        hl = h.lower()
        if hl in RUIDO or any(hl.endswith("." + d) for d in RUIDO):
            continue
        limpios.append(h)
    return limpios


def parse_stdout(output):
    """Extrae emails, hosts e IPs de la salida de texto si falla el JSON."""
    emails = set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', output))
    emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.css', '.js'))}
    hosts = set(re.findall(r'[\w\.-]+\.\w{2,}', output))
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output))
    return {
        "emails": _sin_ruido_emails(list(emails)),
        "hosts": _sin_ruido_hosts(list(hosts)),
        "ips": list(ips)
    }

def run(target, sources="crtsh,certspotter,commoncrawl", limit=500):
    """
    Ejecuta theHarvester sobre un dominio y devuelve los resultados.
    """
    print(f"{Fore.YELLOW}[+] Ejecutando theHarvester sobre: {target}")
    
    # Rutas absolutas
    home = os.path.expanduser("~")
    uv_bin = os.path.join(home, ".local", "bin", "uv")
    harvester_dir = os.path.join(home, "theHarvester")
    
    # Verificamos que existen
    if not os.path.exists(uv_bin):
        return {"error": f"uv no encontrado en {uv_bin}"}
    if not os.path.exists(harvester_dir):
        return {"error": f"theHarvester no encontrado en {harvester_dir}"}
    
    # Creamos la carpeta output si no existe
    if not os.path.exists("output"):
        os.makedirs("output")
    
    output_base = f"output/harvester_{target.replace('.', '_').replace('/', '_')}"
    # Necesitamos la ruta absoluta porque el subprocess se ejecuta en harvester_dir
    output_base_abs = os.path.abspath(output_base)
    
    cmd = [
        uv_bin, "run", "theHarvester",
        "-d", target,
        "-b", sources,
        "-l", str(limit),
        "-f", output_base_abs
    ]
    
    print(f"{Fore.CYAN}    Comando: {' '.join(cmd)}")
    
    try:
        # Limpiamos el VIRTUAL_ENV del OSINT para que uv no se confunda
        env_limpio = os.environ.copy()
        env_limpio.pop("VIRTUAL_ENV", None)
        
        result = subprocess.run(
            cmd,
            cwd=harvester_dir,
            capture_output=True,
            text=True,
            timeout=300,
            env=env_limpio
        )
        
        print(f"{Fore.CYAN}    Return code: {result.returncode}")
        if result.stderr:
            print(f"{Fore.RED}    --- stderr ---")
            print(result.stderr[:1000])
        
        # Intentamos leer el JSON generado
        json_file = f"{output_base_abs}.json"
        if os.path.exists(json_file):
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            emails = _sin_ruido_emails(sorted(set(e for e in data.get("emails", []) if isinstance(e, str))))
            hosts = _sin_ruido_hosts(sorted(set(h for h in data.get("hosts", []) if isinstance(h, str))))
            ips = sorted(set(data.get("ips", [])))
            
            print(f"{Fore.GREEN}    - Emails encontrados: {len(emails)}")
            print(f"{Fore.GREEN}    - Subdominios encontrados: {len(hosts)}")
            print(f"{Fore.GREEN}    - IPs encontradas: {len(ips)}")
            
            return {
                "target": target,
                "emails": emails,
                "subdominios": hosts,
                "ips": ips,
                "fuentes_usadas": sources
            }
        
        # Fallback: parsear stdout
        print(f"{Fore.YELLOW}    - JSON no encontrado, parseando stdout...")
        parsed = parse_stdout(result.stdout or "")
        
        print(f"{Fore.GREEN}    - Emails: {len(parsed['emails'])}")
        print(f"{Fore.GREEN}    - Subdominios: {len(parsed['hosts'])}")
        print(f"{Fore.GREEN}    - IPs: {len(parsed['ips'])}")
        
        return {
            "target": target,
            "emails": parsed["emails"],
            "subdominios": parsed["hosts"],
            "ips": parsed["ips"],
            "fuentes_usadas": sources,
            "nota": "Parseado desde stdout"
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester tardó demasiado (timeout de 5 min)"}
    except Exception as e:
        return {"error": str(e)}
