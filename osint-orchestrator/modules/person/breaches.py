import requests
from colorama import Fore

# Si tienes API Key, ponla aquí. Si no, déjalo vacío para usar el modo simulado.
HIBP_API_KEY = ""

def run(email):
    """Busca el email en HaveIBeenPwned."""
    print(f"{Fore.YELLOW}[+] Buscando brechas para: {email}")
    
    if not HIBP_API_KEY:
        # Modo simulado para pruebas sin API Key
        print(f"{Fore.YELLOW}    - Usando modo simulado (sin API Key)")
        return {
            "email": email,
            "brechas": [
                {"nombre": "Adobe", "fecha": "2013-10-04", "datos_filtrados": ["emails", "passwords"]},
                {"nombre": "LinkedIn", "fecha": "2021-06-22", "datos_filtrados": ["emails", "passwords"]}
            ],
            "modo": "simulado"
        }
    
    # Modo real con API
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "OSINT-Orchestrator"
    }
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            brechas = r.json()
            resultado = [{"nombre": b["Name"], "fecha": b["BreachDate"], "datos": b["DataClasses"]} for b in brechas]
            print(f"{Fore.GREEN}    - Encontradas {len(resultado)} brechas.")
            return {"email": email, "brechas": resultado, "modo": "real"}
        elif r.status_code == 404:
            print(f"{Fore.GREEN}    - No se encontraron brechas.")
            return {"email": email, "brechas": [], "modo": "real"}
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}
