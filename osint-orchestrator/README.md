# OSINT Orchestrator

Orquestador de herramientas OSINT en Python, desarrollado como proyecto del curso de Hacking Ético (preparación OSCP).
Centraliza varias herramientas de código abierto, unifica sus resultados y genera reportes HTML/JSON con grafos interactivos.

> ⚠️ **Uso exclusivamente educativo y en auditorías autorizadas.**
> Investiga solo objetivos propios o para los que tengas permiso explícito. Recopilar datos personales de terceros sin consentimiento puede infringir el RGPD y otras leyes. El autor no se hace responsable del mal uso de la herramienta.

---

## Características

- **Detección automática del tipo de objetivo**: dominio, email, username o teléfono (con confirmación manual para casos ambiguos).
- **Dos modos de uso**:
  - `main.py`: modo rápido o por script, ideal para automatizar.
  - `interactive.py`: investigación guiada con pivotes (*man-in-the-loop*): cada hallazgo puede convertirse en un nuevo objetivo.
- **Cruce de fuentes**: los perfiles encontrados por Sherlock y Maigret se comparan y se clasifican por confianza para reducir falsos positivos.
- **Reportes**: HTML y JSON por objetivo, con nombre personalizable.
- **Grafos interactivos** (vis.js): zoom, arrastre de nodos y clic para abrir la URL de cada hallazgo. En modo interactivo, además, un grafo maestro con toda la sesión.

## Módulos

| Tipo | Módulo | Herramienta / fuente | Qué aporta |
|---|---|---|---|
| Dominio | `web/passive.py` | WHOIS, DNS | Registrador, fechas y registros A, MX, TXT, NS |
| Dominio | `web/theharvester.py` | theHarvester | Emails y subdominios públicos |
| Dominio | `web/active.py` | Nmap + peticiones HTTP | Puertos, servicios y directorios comunes (*ruidoso, pide confirmación*) |
| Email | `person/breaches.py` | Have I Been Pwned | Brechas de datos (modo simulado sin API key) |
| Email | `person/xposedornot.py` | XposedOrNot | Brechas de datos (API gratuita) |
| Email | `person/holehe.py` | Holehe | Servicios donde el email está registrado |
| Username | `person/social.py` | Sherlock | Perfiles en redes sociales |
| Username | `person/maigret.py` | Maigret | Perfiles confirmados y datos públicos del perfil |
| Username | `person/cruce.py` | — | Cruce Sherlock + Maigret con nivel de confianza |
| Teléfono | `person/phone.py` | phonenumbers (offline) | País, operador, tipo de línea y zona horaria |

## Estructura

```
osint-orchestrator/
├── main.py              # Modo rápido / script
├── interactive.py       # Modo interactivo con pivotes
├── requirements.txt
├── modules/
│   ├── person/          # Email, username y teléfono
│   └── web/             # Dominios
├── report/
│   ├── generator.py     # Reportes HTML y JSON
│   ├── graph.py         # Grafos interactivos
│   └── template.html    # Plantilla del reporte
└── output/              # Resultados (ignorado por git)
```

## Instalación

Probado en Linux (Ubuntu/Kali, también dentro de WSL2).

**1. Paquetes del sistema**

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git nmap pipx
```

**2. Entorno virtual y librerías**

```bash
cd osint-orchestrator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**3. Herramientas externas**

```bash
pipx install sherlock-project
pipx install maigret
pipx ensurepath          # después, abre una terminal nueva
```

**4. theHarvester** (opcional, solo para dominios). El módulo lo busca en estas rutas:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh                  # instala uv en ~/.local/bin/uv
git clone https://github.com/laramies/theHarvester.git ~/theHarvester
```

**5. API key de HIBP** (opcional). Sin ella, el módulo funciona en modo simulado:

```bash
export HIBP_API_KEY="tu_api_key"
```

## Uso

Activa siempre el entorno antes de usarla:

```bash
cd osint-orchestrator && source .venv/bin/activate
```

### Modo interactivo (recomendado)

```bash
python3 interactive.py
python3 interactive.py -t usuario.ejemplo --type username   # fuerza el tipo
```

1. Introduce el objetivo y confirma el tipo detectado.
2. Revisa la tabla de hallazgos.
3. Elige sobre qué hallazgos pivotar (por número), `s` para seguir o `f` para terminar.
4. Al final, ponle un nombre a la investigación (por ejemplo `prueba1`) y se generan los ficheros.

### Modo rápido

```bash
python3 main.py                                  # menú
python3 main.py -t ejemplo.com -o all            # dominio, HTML + JSON
python3 main.py -t ejemplo.com --active -y       # sin preguntas (para scripts)
python3 main.py -t "+34600000000" --type phone
```

| Opción | Descripción |
|---|---|
| `-t, --target` | Objetivo. Sin él, abre el menú |
| `-o, --output` | `json`, `html` o `all` |
| `--type` | Fuerza el tipo: `domain`, `email`, `username`, `phone` |
| `--harvester` | Ejecuta theHarvester sin preguntar |
| `--active` | Ejecuta el escaneo activo sin preguntar |
| `-y, --yes` | Responde "sí" a todo |

## Resultados

Todo se guarda en `output/` (excluida de git porque contiene datos de objetivos):

| Fichero | Contenido |
|---|---|
| `nombre.html` | Reporte con todas las secciones del objetivo |
| `nombre.json` | Datos en bruto, para reutilizarlos o procesarlos |
| `nombre_grafo.html` | Grafo interactivo del objetivo |
| `nombre_sesion.html` | Grafo maestro de una sesión con pivotes |

En los grafos de username, los perfiles se colorean según el cruce de fuentes:

- 🟩 **Confirmado**: lo encuentran Sherlock y Maigret.
- 🟨 **Sin confirmar**: solo una herramienta; conviene verificarlo a mano.

## Limitaciones conocidas

- Sherlock puede dar falsos positivos; por eso existe el cruce con Maigret.
- Holehe y Maigret dependen de los servicios consultados y pueden fallar por bloqueos o cambios en ellos.
- Un username con punto (`nombre.apellido`) tiene la misma forma que un dominio: confirma el tipo al empezar.
- Sin `HIBP_API_KEY`, los resultados de HIBP son de ejemplo.

## Créditos

Herramientas de terceros integradas: [Sherlock](https://github.com/sherlock-project/sherlock), [Maigret](https://github.com/soxoj/maigret), [Holehe](https://github.com/megadose/holehe), [theHarvester](https://github.com/laramies/theHarvester), [Nmap](https://nmap.org), [XposedOrNot](https://xposedornot.com), [Have I Been Pwned](https://haveibeenpwned.com), [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) y [pyvis](https://github.com/WestHealth/pyvis).
