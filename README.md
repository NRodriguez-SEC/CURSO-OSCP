# CURSO-OSCP

Repositorio con las tareas y proyectos del curso de **Hacking Ético**, en preparación para la certificación OSCP.
Reúne herramientas y prácticas de reconocimiento, OSINT y seguridad web desarrolladas a lo largo del curso.

> ⚠️ **Uso educativo y autorizado.** Todo el material es para practicar sobre sistemas propios o con permiso explícito (por ejemplo, `scanme.nmap.org` o laboratorios de clase). No debe usarse contra terceros sin autorización.

---

## Contenido

### 🕵️ [OSINT Orchestrator](osint-orchestrator/)

Orquestador de herramientas OSINT en Python. Centraliza varias herramientas de código abierto, unifica sus resultados y genera reportes HTML/JSON con grafos interactivos.

- Objetivos: **dominios, emails, usernames y teléfonos**, con detección automática del tipo.
- Modo rápido ([`main.py`](osint-orchestrator/main.py)) y modo interactivo con pivotes ([`interactive.py`](osint-orchestrator/interactive.py)).
- Integra Sherlock, Maigret, Holehe, theHarvester, Nmap, HIBP y XposedOrNot, y **cruza** los perfiles de Sherlock y Maigret por nivel de confianza.
- Grafos interactivos con nodos clicables y grafo maestro de la sesión.

📖 Documentación completa en su [README](osint-orchestrator/README.md).

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
├── osint-orchestrator/              # Orquestador OSINT
├── analisis-pasivo-activo/          # Suite de reconocimiento y análisis web
└── TAREA 1- ANTICHEAT-CROWDSTRIKE    # Investigación sobre anti-cheat
```

---

## Tecnologías

Python 3, con herramientas OSINT y de pentesting de código abierto (Sherlock, Maigret, Holehe, theHarvester, Nmap) y visualización con pyvis.

## Autor

**Nacho Rodríguez** ([@NRodriguez-SEC](https://github.com/NRodriguez-SEC)) — Curso de Hacking Ético, 2025-2026.
