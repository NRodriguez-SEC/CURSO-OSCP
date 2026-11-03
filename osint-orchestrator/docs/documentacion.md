# Documentación — OSINTBODY

Documentación de uso del orquestador OSINT **OSINTBODY**: despliegue, ejecución y resultados, con capturas y un vídeo de demostración.

## Índice

- [Introducción y Objetivos](#introducción-y-objetivos)
- [Despliegue e Instalación](#despliegue-e-instalación)
- [Ejecución y Resultados](#ejecución-y-resultados)
  - [Prueba 1](#prueba-1)
  - [Prueba 2](#prueba-2)
  - [Prueba 3](#prueba-3)
  - [Prueba 4](#prueba-4)
- [Demostración con un video](#demostración-con-un-video)
- [Conclusión](#conclusión)

---

# Introducción y Objetivos

Un orquestador OSINT es una herramienta que permite reunir y organizar diferentes herramientas de investigación en una sola plataforma.

Nos Facilitara la búsqueda de información en fuentes públicas, automatiza algunos procesos y recopila los resultados para analizarlos.

Su función principal es ahorrar tiempo, relacionar datos y facilitar las investigaciones digitales a grandes grupos o individuos solitarios de forma que se ahorre tiempo en buscar procesos y automatizarlos.

# Despliegue e Instalación

Primero para utilizar nuestra herramienta clonamos nuestro repositorio del compañero para utilizarla, luego activaremos el venv para interpretar el propio Python donde será el interprete que ejecute toda variable.

![Captura 1](capturas/captura-01.png)

![Captura 2](capturas/captura-02.png)

Comprobamos que verdaderamente se ha activado.

![Captura 3](capturas/captura-03.png)

Comprobamos los directorios y vemos un ejecutable comprobamos que tenga permisos de ejecución.

![Captura 4](capturas/captura-04.png)

Instalamos todas las librería y herramientas que necesita nuestra herramienta para que funcione correctamente al ejecutarla.

![Captura 5](capturas/captura-05.png)

Instalando herramientas…

![Captura 6](capturas/captura-06.png)

Nos dirá que todo está preparado y que tenemos incluso una interfaz web donde veremos los resultados.

# Ejecución y Resultados

Empezaremos con una pestaña nueva donde introducimos el directorio de nuevo, activamos venv (interprete) y ponemos el comando “osintbody” que nos mostró la pantalla.

![Captura 7](capturas/captura-07.png)

Nos abre una gran interfaz donde podemos ver que podemos iniciar una interfaz con un documento automático html o ver que tiene nuestro orquestador.

![Captura 8](capturas/captura-08.png)

Si pinchamos en ver módulos disponibles podremos ver que herramienta y que nos puede reconocer: **dominio, username, número y name.**

## Prueba 1

![Captura 9](capturas/captura-09.png)

Ahora si iniciamos una investigación podemos elegir que introducimos.

![Captura 10](capturas/captura-10.png)

![Captura 11](capturas/captura-11.png)

En estas dos opciones se distiguen en que la primera consulta apis directas de github para verificar si hay metadatos y existe.

En cambio, al otro hace una búsqueda masiva en distintas plataformas digitales gracias a whatsmyname.

![Captura 12](capturas/captura-12.png)

Elegimos los dos para mayor profundidad y ejecutamos.

![Captura 13](capturas/captura-13.png)

Inicia la búsqueda.

![Captura 14](capturas/captura-14.png)

Introducimos un nombre donde vemos que la información será guardada.

![Captura 15](capturas/captura-15.png)

Como vemos detecta que es una cuenta de Instagram debido a la búsqueda por whatsmyname.

## Prueba 2

![Captura 16](capturas/captura-16.png)

![Captura 17](capturas/captura-17.png)

Ahora intentare a buscar una amiga donde introduzco su nombre y usuario de Instagram para ver que encuentra.

Nos indica que plataformas usa además de el tipo de consultas con el registro de consultas.

![Captura 18](capturas/captura-18.png)

Marcaremos todas.

![Captura 19](capturas/captura-19.png)

Guardamos.

![Captura 20](capturas/captura-20.png)

Podemos ver el nombre de la compañera donde se podrá ver que es cierto y nombres de posibles cuentas.

## Prueba 3

![Captura 21](capturas/captura-21.png)

Haremos un escaneo WEB donde se introducirá en una pagina con un sistema de peticiones donde consultará las mismas páginas o fuentes.

Esta vez utilice un teléfono de un amiga a ver que tiene.

![Captura 22](capturas/captura-22.png)

Si pinchamos a que no se privado podremos decidir que puede consultar o no.

![Captura 23](capturas/captura-23.png)

Luego en la búsqueda creará un sistema de interfaz que cargarán los módulos junto a los resultados..

![Captura 24](capturas/captura-24.png)

Podremos ver que los resultados de esta cuenta nos dirá que compañía de móvil tiene, distintas cuentas con ese nombre de perfil además que estadística de fiabilidad tiene. 

![Captura 25](capturas/captura-25.png)

![Captura 26](capturas/captura-26.png)

Por ejemplo esto no es una cuenta suya, sin entramos en su enlace.

![Captura 27](capturas/captura-27.png)

## Prueba 4

Ahora haremos prueba con un dominio donde podemos ver que tipo de puertos, rutas, brechas que haya en sitios de leaks y registros además de brechas por la cuenta de email o que tiene registrado (the harvester).

Probare con mi gimnasio y correo aleatorio.

![Captura 28](capturas/captura-28.png)

Iniciamos búsqueda.

![Captura 29](capturas/captura-29.png)

Sobre el correo vemos brechas en varias cuentas como twitter, deezer y phone house.

![Captura 30](capturas/captura-30.png)

Sobre el dominio vemos registros de correo, ips, rutas que podemos explorar para intentar hacer un ataque, subdominios de la propia página. 

![Captura 31](capturas/captura-31.png)

Subdomios…

![Captura 32](capturas/captura-32.png)

Documentos de txt de dns que son interesantes.

![Captura 33](capturas/captura-33.png)

Ip de dos sitios que podemos investigar con shoodan 

![Captura 34](capturas/captura-34.png)

![Captura 35](capturas/captura-35.png)

![Captura 36](capturas/captura-36.png)

Más dominios de seguramente otras aperturas de la misma franquicia.

Por ultimo los propios puertos.

![Captura 37](capturas/captura-37.png)

Falta utilizar otras opciones, video y hacerlo por interfaz gráfica.

# Demostración con un video

> ▶️ **[Ver el vídeo de demostración (`demo.mp4`)](demo.mp4)** — recorrido completo de la herramienta (6:30 min). GitHub lo reproduce al abrir el archivo.

Vemos que podemos obtener un reporte donde veremos un HTML o json con estructura o información útil.

![Captura 38](capturas/captura-38.png)

![Captura 39](capturas/captura-39.png)

Observamos el jason que organiza los selectores para enseñar información de forma visual y concisa.

![Captura 40](capturas/captura-40.png)

![Captura 41](capturas/captura-41.png)

Luego si vamos al report.json organizara la búsqueda por partes primero email, cuentas sociales, dominio con sus registros txt mx y demás información de brechas.

# Conclusión

Me parece que es una herramienta en la cual podemos reconocer entidades o metadatos de la persona con un poco de información pública en segundos de forma que sea útil para nuestras maquinas o reconocimientos de pruebas técnicas asociadas a la <u>OSCP</u>.
