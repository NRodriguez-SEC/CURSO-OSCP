# CURSO-OSCP

Repositorio con las tareas y proyectos del curso de **Hacking Ético**, en preparación para la certificación OSCP.
Reúne herramientas y prácticas de reconocimiento, OSINT y seguridad web desarrolladas a lo largo del curso.

> ⚠️ **Uso educativo y autorizado.** Todo el material es para practicar sobre sistemas propios o con permiso explícito (por ejemplo, `scanme.nmap.org` o laboratorios de clase). No debe usarse contra terceros sin autorización.

---

## Contenido

### 🕵️ [OSINTBODY — Orquestador OSINT](osint-orchestrator/)

Herramienta OSINT modular en Python para consultar información pública a partir de un **correo, nombre de usuario, dominio, teléfono o nombre**. Paquete instalable (`pip install -e .`, comando `osintbody`) con tres interfaces: **CLI**, **TUI** de pantalla completa y **web local** con grafo interactivo.

- Interfaz web (Flask) con **grafo de relaciones** (Cytoscape): arrastrar nodos, inspeccionar evidencia y exportar a PNG.
- Correlación de identidades y **pivotes** entre fuentes; informes en **HTML y JSON** por búsqueda.
- Módulos: brechas, dominio (DNS/WHOIS), theHarvester, teléfono, usernames (dataset WhatsMyName), **perfil de GitHub** y **Wikidata**.
- Modo privado por defecto (solo análisis local); las fuentes externas se activan de forma explícita.
- Con tipado estricto (mypy), linting de seguridad (ruff) y una amplia batería de **tests** (`pytest`).

> Desarrollada de forma conjunta con un compañero; integra el orquestador previo con su herramienta ([osint-footprint-orchestrator](https://github.com/EdwinRincon/osint-footprint-orchestrator)).

📖 Documentación: [README](osint-orchestrator/README.md) y [manual](osint-orchestrator/docs/manual.md). Código en [`src/osint_tool/`](osint-orchestrator/src/osint_tool/).

### 🛡️ [Suite de Reconocimiento y Análisis Web](analisis-pasivo-activo/)

Suite de reconocimiento web con interfaz gráfica, sin frameworks externos (solo la librería estándar de Python).

- [`enumeracion.py`](analisis-pasivo-activo/enumeracion.py) — enumeración pasiva (DNS, WHOIS, crt.sh) y activa (puertos, fuerza bruta de subdominios).
- [`cabeceras_seguridad.py`](analisis-pasivo-activo/cabeceras_seguridad.py) — análisis de cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options…).
- [`servidor_web_scan.py`](analisis-pasivo-activo/servidor_web_scan.py) — servidor web que orquesta los módulos, captura y clasifica User-Agents y exporta reportes en Markdown y HTML.

📖 Documentación completa en su [README](analisis-pasivo-activo/README.md).

### 📄 [Tarea 1 — Sistemas anti-cheat a nivel de kernel](TAREA%201-%20ANTICHEAT-CROWDSTRIKE)

Trabajo de investigación sobre el funcionamiento de los sistemas anti-cheat a nivel de kernel y su arquitectura.

---

## Estructura del repositorio

```
CURSO-OSCP/
├── README.md                        # Este archivo
├── osint-orchestrator/              # OSINTBODY: orquestador OSINT (web, TUI y CLI)
├── analisis-pasivo-activo/          # Suite de reconocimiento y análisis web
└── TAREA 1- ANTICHEAT-CROWDSTRIKE    # Investigación sobre anti-cheat
```

---

## Tecnologías

Python 3, con herramientas OSINT y de pentesting de código abierto (theHarvester, WhatsMyName, Nmap) y visualización de grafos (Cytoscape). Stack de OSINTBODY: Flask, Typer, Textual, Rich, phonenumbers, dnspython.

## Autor

**Nacho Rodríguez** ([@NRodriguez-SEC](https://github.com/NRodriguez-SEC)) — Curso de Hacking Ético, 2025-2026.
