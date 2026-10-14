import subprocess
import shutil
import os
import sys
from colorama import Fore


def run(email):
    """Ejecuta Holehe como subprocess (más fiable que la API de Python)."""
    print(f"{Fore.YELLOW}[+] Ejecutando Holehe para: {email}")
    
    # Buscamos el binario de holehe
    holehe_bin = shutil.which("holehe")
    if not holehe_bin:
        venv_bin = os.path.join(os.path.dirname(sys.executable), "holehe")
        if os.path.exists(venv_bin):
            holehe_bin = venv_bin
        else:
            return {"error": "Holehe no está instalado"}
    
    try:
        result = subprocess.run(
            [holehe_bin, email, "--no-color"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = result.stdout or ""
        sitios = _parsear_salida(output)
        
        if sitios:
            print(f"{Fore.GREEN}    - Registrado en {len(sitios)} sitios.")
        else:
            print(f"{Fore.YELLOW}    - No se encontraron registros confirmados.")
            # Debug: mostrar líneas con símbolos para diagnosticar
            lineas = [l for l in output.split("\n") if l.strip().startswith("[")][:10]
            if lineas:
                print(f"{Fore.CYAN}    Muestra de líneas:")
                for l in lineas:
                    print(f"      {l}")
        
        return {
            "email": email,
            "sitios": sitios,
            "fuente": "Holehe"
        }
    
    except subprocess.TimeoutExpired:
        return {"error": "Holehe tardó demasiado (>5 min)"}
    except Exception as e:
        return {"error": str(e)}


def _parsear_salida(texto):
    """Parsea la salida de Holehe."""
    sitios = []
    vistos = set()
    
    for linea in texto.split("\n"):
        linea = linea.strip()
        
        # Solo [+] (registrado) y [!] (recovery) cuentan como registrado
        if linea.startswith("[+]") or linea.startswith("[!]"):
            resto = linea[3:].strip()
            dominio = resto.split()[0] if resto else ""
            
            if dominio and "." in dominio and dominio not in vistos:
                vistos.add(dominio)
                sitios.append({
                    "sitio": dominio,
                    "registrado": True,
                    "tipo": "confirmado" if linea.startswith("[+]") else "recovery"
                })
    
    return sitios
