import subprocess
import re
from colorama import Fore

def run(username):
    """Ejecuta Sherlock para buscar el username en redes sociales."""
    print(f"{Fore.YELLOW}[+] Buscando '{username}' en redes sociales con Sherlock...")
    
    try:
        # Ejecutamos Sherlock y capturamos la salida
        result = subprocess.run(
            ['sherlock', username, '--print-found', '--timeout', '10'],
            capture_output=True, text=True, timeout=120
        )
        
        # Parsear la salida de texto para extraer las URLs encontradas
        perfiles = []
        for line in result.stdout.split('\n'):
            # Sherlock imprime líneas como: "[+] GitHub: https://github.com/username"
            if line.startswith('[+]'):
                match = re.search(r'\[\+\] (.+?): (https?://\S+)', line)
                if match:
                    perfiles.append({
                        "red": match.group(1).strip(),
                        "url": match.group(2).strip()
                    })
        
        if perfiles:
            print(f"{Fore.GREEN}    - Encontrados {len(perfiles)} perfiles.")
        else:
            print(f"{Fore.YELLOW}    - No se encontraron perfiles públicos.")
            
        return {"username": username, "perfiles": perfiles}
        
    except FileNotFoundError:
        return {"error": "Sherlock no está instalado. Ejecuta: pip install sherlock-project"}
    except subprocess.TimeoutExpired:
        return {"error": "Sherlock tardó demasiado"}
    except Exception as e:
        return {"error": str(e)}
