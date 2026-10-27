#!/usr/bin/env bash
#
# install.sh - Monta todo lo necesario para OSINT Orchestrator.
# Uso:   ./install.sh            (instala todo)
#        ./install.sh --no-harvester   (omite theHarvester)
#
# Pensado para Linux con apt (Ubuntu, Kali, incluido WSL).

set -u  # falla al usar variables sin definir; NO usamos -e para poder avisar y seguir

VERDE='\033[0;32m'; AMARILLO='\033[1;33m'; ROJO='\033[0;31m'; AZUL='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${AZUL}[*]${NC} $1"; }
ok()    { echo -e "${VERDE}[+]${NC} $1"; }
aviso() { echo -e "${AMARILLO}[!]${NC} $1"; }
error() { echo -e "${ROJO}[x]${NC} $1"; }

INSTALAR_HARVESTER=1
[ "${1:-}" = "--no-harvester" ] && INSTALAR_HARVESTER=0

# Trabajamos siempre en la carpeta del script
cd "$(dirname "$0")" || exit 1

echo "============================================="
echo "   OSINT Orchestrator - Instalación"
echo "============================================="

# 1) Paquetes del sistema
info "Paquetes del sistema (necesita sudo)..."
if command -v apt >/dev/null 2>&1; then
    sudo apt update -qq && sudo apt install -y python3 python3-venv python3-pip git nmap pipx \
        && ok "Paquetes del sistema instalados." \
        || aviso "Algún paquete del sistema falló; revisa la salida de apt."
else
    aviso "No se encontró 'apt'. Instala a mano: python3, python3-venv, git, nmap, pipx."
fi

# 2) Entorno virtual + librerías Python
info "Creando entorno virtual (.venv)..."
python3 -m venv .venv && ok "Entorno virtual creado." || { error "No se pudo crear el venv."; exit 1; }
# shellcheck disable=SC1091
source .venv/bin/activate

info "Instalando librerías de requirements.txt..."
pip install --quiet --upgrade pip
if pip install --quiet -r requirements.txt; then
    ok "Librerías Python instaladas."
else
    aviso "Falló la instalación de requirements.txt (posible conflicto, p. ej. holehe/ignorant)."
    aviso "Revisa la salida; puede que haya que fijar una versión de alguna dependencia."
fi

# 3) Herramientas externas con pipx (fuera del venv, aisladas)
info "Instalando Sherlock y Maigret con pipx..."
if command -v pipx >/dev/null 2>&1; then
    pipx install sherlock-project 2>/dev/null || aviso "Sherlock ya instalado o falló."
    pipx install maigret         2>/dev/null || aviso "Maigret ya instalado o falló."
    pipx ensurepath >/dev/null 2>&1
    ok "pipx listo (abre una terminal NUEVA para que el PATH surta efecto)."
else
    aviso "pipx no disponible. Instala Sherlock y Maigret a mano: pipx install sherlock-project maigret"
fi

# 4) theHarvester (opcional) en las rutas que espera el módulo
if [ "$INSTALAR_HARVESTER" -eq 1 ]; then
    info "Instalando theHarvester..."
    if [ ! -f "$HOME/.local/bin/uv" ]; then
        curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 \
            && ok "uv instalado." || aviso "No se pudo instalar uv (theHarvester lo necesita)."
    else
        ok "uv ya estaba instalado."
    fi
    if [ ! -d "$HOME/theHarvester" ]; then
        git clone --quiet https://github.com/laramies/theHarvester.git "$HOME/theHarvester" \
            && ok "theHarvester clonado en ~/theHarvester." || aviso "No se pudo clonar theHarvester."
    else
        ok "theHarvester ya estaba en ~/theHarvester."
    fi
else
    aviso "theHarvester omitido (--no-harvester)."
fi

echo
echo "============================================="
ok "Instalación terminada."
echo "============================================="
echo
echo "Siguientes pasos:"
echo "  1) Abre una terminal NUEVA (para el PATH de pipx)."
echo "  2) cd $(pwd)"
echo "  3) source .venv/bin/activate"
echo "  4) python3 interactive.py"
echo
echo "Opcional: export HIBP_API_KEY=\"tu_api_key\"  para datos reales de HIBP."
