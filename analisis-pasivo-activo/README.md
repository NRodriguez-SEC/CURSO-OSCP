# 🛡️ Suite de Reconocimiento y Análisis Web en Python

Proyecto de ciberseguridad desarrollado como práctica de la asignatura **Seguridad Ofensiva / Hacking Ético**.

Incluye herramientas de **enumeración pasiva y activa**, **análisis de cabeceras de seguridad HTTP**, **captura y análisis de User-Agents**, y una **interfaz web** con exportación automática de reportes en Markdown y HTML.

> ⚠️ **Uso educativo**: Estas herramientas están diseñadas exclusivamente para practicar sobre sistemas propios o autorizados (por ejemplo, `scanme.nmap.org` o laboratorios propios). No deben usarse contra sistemas de terceros sin permiso explícito.

---

## 📋 Tabla de contenidos

- [Características](#-características)
- [Instalación](#-instalación)
- [Arquitectura](#-arquitectura)
- [🌐 Servidor web](#-servidor-web)
- [💻 Uso desde línea de comandos](#-uso-desde-línea-de-comandos)
- [🧪 Pruebas](#-pruebas)
- [🔬 Detalles técnicos](#-detalles-técnicos)
- [📁 Estructura del proyecto](#-estructura-del-proyecto)
- [📚 Referencias](#-referencias)

---

## ✨ Características

| Módulo | Descripción |
|---|---|
| 🔍 **Enumeración pasiva** | DNS, WHOIS, subdominios vía Certificate Transparency (crt.sh) |
| 🎯 **Enumeración activa** | Escaneo de puertos TCP con banner grabbing, fuerza bruta de subdominios con detección de DNS comodín |
| 🛡️ **Cabeceras de seguridad** | Análisis de HSTS, CSP, X-Frame-Options, etc. + detección de información filtrada (`Server`, `X-Powered-By`) |
| 🕵️ **Captura de User-Agents** | Servidor HTTP que registra y clasifica todos los UAs entrantes |
| 🧪 **Laboratorio de User-Agents** | Analizador interactivo con `ua-parser` |
| 🔄 **Rotación de User-Agents** | Evasión de WAFs usando UAs realistas en cada escaneo |
| 📥 **Exportación de reportes** | Generación automática en Markdown y HTML |
| 🌐 **Interfaz web completa** | Sin frameworks externos, solo `http.server` de la stdlib |

---

## 🚀 Instalación

### Requisitos previos

- Python 3.10 o superior
- pip
- (Opcional) `ua-parser` para análisis profesional de User-Agents

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO

# 2. Crear un entorno virtual
python3 -m venv venv
source venv/bin/activate    # En Windows: venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt
```

---

## 🏗️ Arquitectura

El proyecto se compone de **tres módulos Python independientes** que también se pueden usar de forma conjunta:

```
┌──────────────────────────────────────────────────────────┐
│                servidor_web_scan.py                       │
│  (servidor HTTP + interfaz web + API REST + reportes)    │
└───────────────┬──────────────────────┬───────────────────┘
                │                      │
                │ importa              │ importa
                ▼                      ▼
┌───────────────────────┐  ┌──────────────────────────────┐
│   enumeracion.py      │  │  cabeceras_seguridad.py      │
│  (DNS, WHOIS, crt.sh) │  │  (HSTS, CSP, XFO, etc.)      │
└───────────────────────┘  └──────────────────────────────┘
```

Cada módulo funciona **de forma autónoma** desde CLI, pero el servidor web los orquesta para ofrecer una interfaz gráfica.

---

## 🌐 Servidor web

### Arranque

```bash
# Puerto por defecto (8080)
python3 servidor_web_scan.py

# Puerto personalizado
python3 servidor_web_scan.py 8081
```

Salida esperada:

```
Servidor en http://localhost:8080
  · Panel UA   → http://localhost:8080/
  · Escáner    → http://localhost:8080/scan
  · Lab UA     → http://localhost:8080/ua-lab
  · ua-parser  → OK
```

### Páginas disponibles

#### 🏠 `/` — Panel de User-Agents

Muestra en **tiempo real** (refresco cada 2 s):

- Tarjetas con el navegador, versión, sistema operativo, dispositivo y tipo del cliente actual.
- El User-Agent completo en texto plano.
- Tabla con las **últimas 100 peticiones** recibidas, con IP, ruta, navegador, versión, SO, dispositivo, tipo y UA crudo.

**Cómo generar tráfico**: visita la página desde varios navegadores, usa `curl` con distintos UA, o conecta desde tu móvil apuntando a `http://TU_IP_LOCAL:8080/`.

#### 🔍 `/scan` — Escáner web

Formulario con:

- Campo de texto para el **objetivo** (dominio o URL).
- Tres checkboxes de **técnicas**:
  - **Cabeceras de seguridad** — analiza HSTS, CSP, XFO, etc.
  - **Enumeración pasiva** — DNS + WHOIS + crt.sh.
  - **Enumeración activa** — puertos TCP + fuerza bruta de subdominios.

Durante el escaneo verás un **log en vivo** con cada paso. Al terminar, dos botones de descarga:

- **⬇ Markdown (.md)** — reporte formateado para pegar en Word/PDF.
- **⬇ HTML (.html)** — reporte con estilos, autocontenido, listo para abrir en cualquier navegador.

#### 🧪 `/ua-lab` — Laboratorio de User-Agents

Analizador interactivo de UAs:

- Botones con **12 ejemplos predefinidos** (Chrome, Firefox, Safari, Edge, curl, Wget, python-requests, Googlebot, Nikto, sqlmap…).
- Campo de texto para pegar cualquier UA.
- Resultado con tarjetas: navegador, versión, sistema, dispositivo, tipo.
- Vista **JSON cruda** del análisis completo.

### API REST interna

El servidor expone endpoints JSON que se pueden consumir desde cualquier cliente:

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/api/registro` | Devuelve el UA del cliente y las últimas 100 peticiones |
| `GET` | `/api/motor` | Indica si `ua-parser` está activo o se usa el fallback |
| `POST` | `/api/ua/parse` | Analiza un User-Agent (`{"ua": "..."}`) |
| `POST` | `/api/scan` | Lanza un escaneo (`{"target": "...", "tipos": ["cabeceras","pasiva","activa"]}`) |
| `GET` | `/api/scan/<id>` | Consulta el estado y resultados de un escaneo |
| `GET` | `/api/scan/<id>/report.md` | Descarga el reporte en Markdown |
| `GET` | `/api/scan/<id>/report.html` | Descarga el reporte en HTML |

Ejemplo de uso desde `curl`:

```bash
# Analizar un UA
curl -X POST -H "Content-Type: application/json" \
  -d '{"ua":"sqlmap/1.7.2#stable (http://sqlmap.org)"}' \
  http://localhost:8080/api/ua/parse
```

```bash
# Lanzar un escaneo y guardar el id
curl -X POST -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","tipos":["cabeceras","pasiva"]}' \
  http://localhost:8080/api/scan
# → {"id":"1"}
```

```bash
# Consultar el resultado del escaneo 1
curl http://localhost:8080/api/scan/1 | python3 -m json.tool

# Descargar el reporte
curl -O http://localhost:8080/api/scan/1/report.md
```

---

## 💻 Uso desde línea de comandos

### Enumeración

```bash
# Enumeración pasiva
python3 enumeracion.py scanme.nmap.org --pasiva

# Enumeración activa (requiere autorización)
python3 enumeracion.py scanme.nmap.org --activa

# Ambas
python3 enumeracion.py scanme.nmap.org --pasiva --activa

# Guardar la salida en un archivo
python3 enumeracion.py scanme.nmap.org --pasiva --activa > reporte.txt 2>&1
```

### Análisis de cabeceras

```bash
python3 cabeceras_seguridad.py https://github.com
python3 cabeceras_seguridad.py https://google.com
python3 cabeceras_seguridad.py http://localhost:8080
```

---

## 🧪 Pruebas

### Pruebas web

#### 1. Panel de User-Agents

Abre `http://localhost:8080/` en el navegador. Verás tu UA clasificado. Luego, desde **otra pestaña** o **terminal**, genera tráfico y observa el panel actualizarse.

**Desde el móvil** (misma red Wi-Fi):

```bash
# Averigua tu IP local
ipconfig              # Windows
ifconfig | grep inet  # Linux/macOS
```

Abre en el móvil `http://TU_IP_LOCAL:8080/`. En el panel verás una nueva entrada con `Safari / iOS / Móvil`.

> 💡 Si no funciona, el firewall bloquea el puerto. En Windows:
> ```powershell
> New-NetFirewallRule -DisplayName "Python UA Server" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
> ```

#### 2. Escáner web

Abre `http://localhost:8080/scan` y prueba:

| Prueba | Objetivo | Técnicas |
|---|---|---|
| Análisis rápido | `https://github.com` | Cabeceras |
| Enumeración pasiva | `scanme.nmap.org` | Cabeceras + Pasiva |
| Escaneo completo | `scanme.nmap.org` | Todas |
| Análisis propio | `http://localhost:8080` | Cabeceras |

Al terminar, descarga el **Markdown** y el **HTML** y observa los reportes generados.

#### 3. Laboratorio de User-Agents

Abre `http://localhost:8080/ua-lab` y prueba a pulsar los botones de ejemplos. Fíjate especialmente en:

- **sqlmap** → clasificado como `Herramienta`.
- **Googlebot** → clasificado como `Bot`.
- **Safari iPhone** → clasificado como `Móvil` con SO `iOS`.
- **Nikto** → clasificado como `Herramienta`.

### Pruebas por línea de comandos

#### 1. Generar tráfico con distintos clientes

Con el servidor corriendo, ejecuta cada comando en otra terminal:

```bash
# Cliente normal de curl (UA por defecto)
curl http://localhost:8080/

# Cliente falso personalizado
curl -A "Soy un cliente inventado/1.0" http://localhost:8080/

# Simular un iPhone
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" http://localhost:8080/

# Simular un bot de Google
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://localhost:8080/

# Simular un escáner de vulnerabilidades
curl -A "Nikto/2.1.6" http://localhost:8080/

# Simular sqlmap (para probar clasificación)
curl -A "sqlmap/1.7.2#stable (http://sqlmap.org)" http://localhost:8080/

# Simular Wget
wget -qO- http://localhost:8080/ 2>/dev/null || curl -A "Wget/1.21.3" http://localhost:8080/

# Petición POST
curl -X POST -A "Cliente POST/1.0" http://localhost:8080/
```

Después recarga el panel web (`Ctrl + F5`) y comprueba la clasificación.

#### 2. Probar la API de análisis de UA

```bash
# UA de Chrome en Windows
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}' \
  http://localhost:8080/api/ua/parse | python3 -m json.tool
```

Salida esperada:

```json
{
  "navegador": "Chrome",
  "version": "120",
  "so": "Windows 10",
  "dispositivo": "Other",
  "tipo": "Escritorio",
  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "motor_parseo": "ua-parser"
}
```

Prueba también con:

```bash
# sqlmap
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"ua":"sqlmap/1.7.2#stable (http://sqlmap.org)"}' \
  http://localhost:8080/api/ua/parse | python3 -m json.tool

# Googlebot
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"ua":"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}' \
  http://localhost:8080/api/ua/parse | python3 -m json.tool
```

#### 3. Flujo completo vía API (sin navegador)

```bash
# 1. Lanzar un escaneo
SID=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","tipos":["cabeceras","pasiva","activa"]}' \
  http://localhost:8080/api/scan | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "ID del escaneo: $SID"

# 2. Consultar el estado hasta que termine
while true; do
  ESTADO=$(curl -s http://localhost:8080/api/scan/$SID | python3 -c "import sys,json;print(json.load(sys.stdin)['estado'])")
  echo "Estado: $ESTADO"
  [ "$ESTADO" = "completado" ] && break
  sleep 2
done

# 3. Descargar los reportes
curl -o reporte.md http://localhost:8080/api/scan/$SID/report.md
curl -o reporte.html http://localhost:8080/api/scan/$SID/report.html

# 4. Ver el Markdown en la terminal
cat reporte.md
```

#### 4. Ver el log de User-Agents en vivo

```bash
# Linux / macOS
tail -f useragents.log

# Windows PowerShell
Get-Content useragents.log -Wait -Tail 20
```

### Pruebas de evasión con User-Agents

#### 1. Comparar análisis de distintos UAs

```bash
# Todos estos comandos deberían clasificarse distinto
curl -s -X POST -H "Content-Type: application/json" -d '{"ua":"curl/8.4.0"}' http://localhost:8080/api/ua/parse
curl -s -X POST -H "Content-Type: application/json" -d '{"ua":"python-requests/2.31.0"}' http://localhost:8080/api/ua/parse
curl -s -X POST -H "Content-Type: application/json" -d '{"ua":"sqlmap/1.7.2#stable"}' http://localhost:8080/api/ua/parse
curl -s -X POST -H "Content-Type: application/json" -d '{"ua":"Nikto/2.1.6"}' http://localhost:8080/api/ua/parse
```

**Utilidad en pentesting**: estas herramientas (`curl`, `python-requests`, `sqlmap`, `Nikto`) son **bloqueadas por defecto** por muchos WAFs. Cambiar el UA a uno de navegador real es la primera técnica de evasión.

#### 2. Comprobar la rotación de User-Agents en los escaneos

Lanza varios escaneos con la misma URL y observa en cada uno el UA diferente:

```bash
for i in 1 2 3; do
  SID=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"target":"https://github.com","tipos":["cabeceras"]}' \
    http://localhost:8080/api/scan | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
  sleep 3
  curl -s http://localhost:8080/api/scan/$SID | \
    python3 -c "import sys,json;d=json.load(sys.stdin);print('Escaneo',d['id'],'→',d['resultados']['cabeceras']['ua_usado'][:80])"
done
```

Cada escaneo debería mostrar un UA diferente (Chrome Windows, Firefox, Safari macOS…). Esto demuestra la **rotación de User-Agents** implementada en `analizar_cabeceras()`.

---

## 🔬 Detalles técnicos

- **Lenguaje**: Python 3
- **Dependencias**: `ua-parser` (opcional, con fallback interno)
- **Concurrencia**: `ThreadPoolExecutor` para escaneo paralelo de puertos y subdominios
- **Servidor HTTP**: `http.server.ThreadingHTTPServer` (sin frameworks externos)
- **Rotación de User-Agents**: 6 UAs realistas para evasión de WAFs
- **Async**: los escaneos se ejecutan en hilos en segundo plano; el navegador hace *polling* cada segundo
- **Reportes**: generación dinámica desde las estructuras de datos en memoria
- **Sin dependencias pesadas**: solo stdlib + `ua-parser`

---

## 📁 Estructura del proyecto

```
.
├── enumeracion.py             # Enumeración pasiva y activa
├── cabeceras_seguridad.py     # Análisis de cabeceras HTTP
├── servidor_web_scan.py       # Servidor web + escáner + lab UA
├── requirements.txt           # Dependencias
├── README.md                  # Este archivo
└── .gitignore
```

---

## 📚 Referencias

- [PEP 668 – Externally Managed Environments](https://peps.python.org/pep-0668/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN – User-Agent header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
- [crt.sh – Certificate Transparency](https://crt.sh/)
- [ua-parser/uap-python](https://github.com/ua-parser/uap-python)

---

## ⚖️ Licencia

Este proyecto se distribuye con fines **exclusivamente educativos**.

---

**Autor**: Nacho Rodriguez  
**Asignatura**: OSINT  
**Curso**: 2025-2026
