import subprocess
import json
import os
import shutil
import tempfile
from colorama import Fore


def run(username):
    """Ejecuta Maigret y devuelve perfiles confirmados + datos extraídos."""
    print(f"{Fore.YELLOW}[+] Buscando '{username}' con Maigret (puede tardar ~20s)...")

    tmp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(
            ["maigret", username, "--json", "simple",
             "--folderoutput", tmp_dir, "--timeout", "15"],
            capture_output=True, text=True, timeout=300
        )

        json_path = os.path.join(tmp_dir, f"report_{username}_simple.json")
        if not os.path.exists(json_path):
            return {"error": "Maigret no generó salida", "perfiles": []}

        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        perfiles = []
        for sitio, info in data.items():
            if not isinstance(info, dict):
                continue

            st = info.get("status", {})
            # Estructura: info["status"]["status"] == "Claimed"
            if not isinstance(st, dict) or st.get("status") != "Claimed":
                continue

            perfiles.append({
                "red": st.get("site_name", sitio),
                "url": info.get("url_user", ""),
                "extra": st.get("ids", {}),   # uid, fechas, país...
            })

        if perfiles:
            print(f"{Fore.GREEN}    - Maigret encontró {len(perfiles)} perfiles.")
        else:
            print(f"{Fore.YELLOW}    - Maigret no confirmó perfiles.")

        return {"username": username, "perfiles": perfiles, "fuente": "Maigret"}

    except FileNotFoundError:
        return {"error": "Maigret no instalado: pipx install maigret", "perfiles": []}
    except subprocess.TimeoutExpired:
        return {"error": "Maigret tardó demasiado", "perfiles": []}
    except Exception as e:
        return {"error": str(e), "perfiles": []}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
