#!/usr/bin/env bash
#
# install.sh - Monta todo lo necesario para OSINTBODY.
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

# Trabajamos siempre en la carpeta del script (donde está pyproject.toml)
cd "$(dirname "$0")" || exit 1

echo "============================================="
echo "   OSINTBODY - Instalación"
echo "============================================="

# 1) Paquetes del sistema
info "Paquetes del sistema (necesita sudo)..."
if command -v apt >/dev/null 2>&1; then
    sudo apt update -qq && sudo apt install -y python3 python3-venv python3-pip git pipx \
        && ok "Paquetes del sistema instalados." \
        || aviso "Algún paquete del sistema falló; revisa la salida de apt."
else
    aviso "No se encontró 'apt'. Instala a mano: python3, python3-venv, python3-pip, git, pipx."
fi

# 2) Entorno virtual + el propio paquete con sus dependencias
info "Creando entorno virtual (.venv)..."
python3 -m venv .venv && ok "Entorno virtual creado." || { error "No se pudo crear el venv."; exit 1; }
# shellcheck disable=SC1091
source .venv/bin/activate

info "Instalando OSINTBODY y sus dependencias (pip install -e .[dev])..."
pip install --quiet --upgrade pip
if pip install --quiet -e ".[dev]"; then
    ok "OSINTBODY instalado (comando 'osintbody' disponible en el venv)."
else
    error "Falló 'pip install -e .[dev]'. Revisa la salida de pip."
fi

# 3) theHarvester (opcional). En Kali/Debian es un paquete apt que deja el
#    comando 'theHarvester' en el PATH. NO se instala con pipx (no expone app).
if [ "$INSTALAR_HARVESTER" -eq 1 ]; then
    info "Instalando theHarvester (paquete del sistema)..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt install -y theharvester && ok "theHarvester instalado." \
            || aviso "No se pudo instalar 'theharvester' por apt. Instálalo según su wiki (uv)."
    else
        aviso "Sin apt. Instala theHarvester según github.com/laramies/theHarvester (uv)."
    fi
else
    aviso "theHarvester omitido (--no-harvester). El módulo de dominios lo saltará."
fi

# 4) Holehe e ignorant (opcionales): cuentas por email y por teléfono
info "Instalando Holehe e ignorant con pipx (fuentes opcionales)..."
if command -v pipx >/dev/null 2>&1; then
    pipx install holehe   2>/dev/null && ok "Holehe instalado."   || aviso "Holehe ya instalado o falló (se omite si no está)."
    pipx install ignorant 2>/dev/null && ok "ignorant instalado." || aviso "ignorant ya instalado o falló (se omite si no está)."
    pipx ensurepath >/dev/null 2>&1
else
    aviso "pipx no disponible. Instala a mano: pipx install holehe ignorant"
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
echo "  4) osintbody            # interfaz de terminal (TUI); dentro, 'Abrir sitio web'"
echo
echo "Verificación (opcional):  pytest    ·    ruff check src    ·    mypy src"
echo "Los informes se guardan en la carpeta  output/"
