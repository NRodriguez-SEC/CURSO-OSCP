import json
import os
import re
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from colorama import Fore

def _generar_nombre_base(reporte):
    """Crea un nombre de archivo único basado en el target y la fecha."""
    # Limpiamos el target para que sea seguro como nombre de archivo
    # Ejemplo: "https://example.com/path" -> "example.com_path"
    target_limpio = re.sub(r'[^a-zA-Z0-9.-]', '_', reporte["target"])
    # Añadimos la fecha y hora
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{target_limpio}_{fecha}"

def generate_json(data, filename=None):
    """Guarda los datos en formato JSON con nombre único."""
    if filename is None:
        nombre_base = _generar_nombre_base(data)
        filename = f"output/{nombre_base}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, default=str, ensure_ascii=False)
    print(f"{Fore.GREEN}[*] Reporte JSON guardado en: {filename}")
    return filename

def generate_html(data, filename=None):
    """Genera un reporte HTML con nombre único."""
    if filename is None:
        nombre_base = _generar_nombre_base(data)
        filename = f"output/{nombre_base}.html"
    
    env = Environment(loader=FileSystemLoader('report'))
    template = env.get_template('template.html')
    html_output = template.render(reporte=data)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_output)
    print(f"{Fore.GREEN}[*] Reporte HTML guardado en: {filename}")
    return filename
