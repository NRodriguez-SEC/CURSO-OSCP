import requests
from colorama import Fore

def run(email):
    """
    Consulta XposedOrNot para un email.
    La API devuelve una estructura como: {"breaches": [["Adobe", "LinkedIn"]], "status": "success"}
    """
    print(f"{Fore.YELLOW}[+] Consultando XposedOrNot para: {email}")
    
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    
    try:
        r = requests.get(url, timeout=15)
        
        # 404: no hay brechas para ese email
        if r.status_code == 404:
            print(f"{Fore.GREEN}    - No se encontraron brechas en XposedOrNot.")
            return {"email": email, "brechas": [], "fuente": "XposedOrNot"}
        
        if r.status_code != 200:
            print(f"{Fore.RED}    - Error HTTP {r.status_code}")
            return {"error": f"HTTP {r.status_code}"}
        
        data = r.json()
        
        # La API devuelve "breaches" como una lista de listas: [["Adobe", "LinkedIn", ...]]
        # Aplanamos la lista para tener solo los nombres
        brechas_raw = data.get("breaches", [])
        nombres_brechas = []
        
        if isinstance(brechas_raw, list):
            for item in brechas_raw:
                if isinstance(item, list):
                    # Caso real de XposedOrNot: lista anidada de strings
                    nombres_brechas.extend([str(b) for b in item])
                elif isinstance(item, dict):
                    # Por si en el futuro cambian a diccionarios
                    nombres_brechas.append(item.get("name", "Desconocido"))
                else:
                    nombres_brechas.append(str(item))
        
        # Convertimos a lista de diccionarios (sin fecha ni datos, no los da esta API)
        brechas = [{"nombre": nombre, "fecha": "N/A", "datos_filtrados": []} for nombre in nombres_brechas]
        
        if brechas:
            print(f"{Fore.GREEN}    - Encontradas {len(brechas)} brechas.")
        else:
            print(f"{Fore.YELLOW}    - No se encontraron brechas.")
        
        return {
            "email": email,
            "brechas": brechas,
            "fuente": "XposedOrNot"
        }
        
    except requests.RequestException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
