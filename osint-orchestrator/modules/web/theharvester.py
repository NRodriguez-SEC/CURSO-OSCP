import subprocess
import json
import os
import re
from colorama import Fore

def parse_stdout(output):
    """Extrae emails, hosts e IPs de la salida de texto si falla el JSON."""
    emails = set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', output))
    emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.css', '.js'))}
    hosts = set(re.findall(r'[\w\.-]+\.\w{2,}', output))
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output))
    return {
        "emails": list(emails),
        "hosts": list(hosts),
        "ips": list(ips)
    }

def run(target, sources="crtsh,certspotter,commoncrawl", limit=500):
    """
    Ejecuta theHarvester sobre un dominio y devuelve los resultados.
    
    Args:
        target: Dominio a analizar (ej: example.com)
        sources: Fuentes a consultar (por defecto: crtsh,certspotter,commoncrawl)
        limit: Límite de resultados por fuente
    
    Returns:
        Diccionario con emails, subdominios e IPs encontradas.
    """
    print(f"{Fore.YELLOW}[+] Ejecutando theHarvester sobre: {target}")
    
    # Limpiamos el nombre del archivo de salida
    output_base = f"output/harvester_{target.replace('.', '_').replace('/', '_')}"
    
    cmd = [
        "theHarvester",
        "-d", target,
        "-b", sources,
        "-l", str(limit),
        "-f", output_base
    ]
    
    try:
        # Ejecutamos theHarvester con timeout de 5 minutos
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # Intentamos leer el JSON generado por theHarvester
        json_file = f"{output_base}.json"
        if os.path.exists(json_file):
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Normalizamos los resultados (theHarvester puede devolver listas vacías)
            emails = data.get("emails", [])
            hosts = data.get("hosts", [])
            ips = data.get("ips", [])
            
            # Limpiamos y deduplicamos
            emails = sorted(set(e for e in emails if isinstance(e, str)))
            hosts = sorted(set(h for h in hosts if isinstance(h, str)))
            ips = sorted(set(ips))
            
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
        else:
            # Fallback: parsear stdout si no se generó el JSON
            print(f"{Fore.YELLOW}    - JSON no encontrado, parseando salida de texto...")
            parsed = parse_stdout(result.stdout)
            return {
                "target": target,
                "emails": parsed["emails"],
                "subdominios": parsed["hosts"],
                "ips": parsed["ips"],
                "fuentes_usadas": sources,
                "nota": "Resultados parseados desde stdout"
            }
            
    except subprocess.TimeoutExpired:
        return {"error": "theHarvester tardó demasiado (timeout de 5 min)"}
    except FileNotFoundError:
        return {"error": "theHarvester no está instalado. Ejecuta: pip install theHarvester"}
    except Exception as e:
        return {"error": str(e)}
