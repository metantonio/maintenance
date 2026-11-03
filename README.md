# 🛡️ NetShield & DiskCleaner Pro

Suite en Python para análisis de redes Wi-Fi, auditoría de ciberseguridad (detección de espionaje/intervención) y diagnóstico/mantenimiento de espacio en disco en Windows.

---

## 🚀 Inicio Rápido (Un Clic)

Puedes ejecutar la aplicación de tres formas:

1. **Ejecutable Standalone (.EXE sin necesidad de Python)**:
   - Ve a la carpeta `dist/` y haz doble clic en **`NetShieldPro.exe`**.
   - No requiere tener Python instalado; incluye todo lo necesario.

2. **Lanzador Directo**:
   - Haz doble clic en **`iniciar_herramienta.bat`** o **`run.bat`**.
   - Configura el entorno virtual automáticamente y abre la GUI.

3. **Recompilar el .EXE cuando desees**:
   - Haz doble clic en **`build_exe.bat`**.
   - Compilará de nuevo el archivo `dist/NetShieldPro.exe` usando PyInstaller.

---

## 📋 Módulos y Funcionalidades

### 1. 📶 Wi-Fi & Red Local
- **Detalles de la Conexión Activa**: SSID, BSSID (MAC del Punto de Acceso), Canal, Banda (2.4 GHz / 5 GHz / 6 GHz), Tipo de Radio (802.11ax/ac), Señal (%), RSSI (dBm) y velocidad en Mbps.
- **Auditoría de Cifrado**: Detecta si la red es abierta (sin contraseña), usa cifrados obsoletos y vulnerables (WEP, WPA-TKIP) o protocolos seguros (WPA2-CCMP, WPA3).
- **Puerta de Enlace & DNS**: Identifica la IP y MAC del Router (Gateway), fabricante y servidores DNS configurados (Google, Cloudflare, Quad9, VPN/Tailscale o ISP).

### 2. 💻 Explorador de Dispositivos en Red (LAN Scanner)
- **Escaneo Multihilo Ultrarrápido**: Emplea llamadas Win32 nativas (`iphlpapi.SendARP`) y sockets en paralelo para descubrir en 2-4 segundos todos los dispositivos conectados a tu subred.
- **Resolución de Fabricante (OUI)**: Base de datos local integrada con más de 300 fabricantes (Apple, Samsung, Xiaomi, Huawei, ZTE, Intel, Qualcomm, Raspberry Pi, etc.) y detección de direcciones MAC aleatorias/privadas de móviles (iOS/Android).
- **Resolución de Nombres & Puertos**: Resuelve hostnames por DNS inverso y escanea puertos clave (80, 443, 22, 445, 8080).

### 3. 🛡️ Auditoría de Ciberseguridad & Anti-Hacking
- **Detección de Envenenamiento ARP (MitM)**: Comprueba si la MAC del router está asignada a otra IP o si hay direcciones físicas duplicadas que indiquen un ataque Man-In-The-Middle para interceptar tu tráfico.
- **Integridad de DNS (Anti-Hijacking)**: Evalúa si tus peticiones DNS están siendo desviadas a servidores no autorizados o IPs locales maliciosas.
- **Auditoría de Puertos en Escucha (Listeners)**: Analiza qué procesos de tu PC tienen puertos abiertos expuestos a la red local (`0.0.0.0` o `::`), alertando sobre puertos sospechosos de troyanos o herramientas de control remoto no deseadas.
- **Puntuación de Seguridad (Score 0-100)**: Semáforo visual con recomendaciones específicas en español.

### 4. 📈 Rastreador de Archivos Recientes (Últimos 7 Días)
- **Diagnóstico de Pérdida de Espacio**: Escaneo optimizado con `os.scandir` para localizar los archivos que más espacio han devorado en los últimos 7 días (configurable a 3, 7, 14 o 30 días).
- **Ranking de Archivos Pesados**: Lista ordenada por tamaño (descargas olvidadas, vídeos, imágenes ISO y especialmente volcados de error `.dmp`).
- **Botón Directo "Abrir"**: Permite abrir el Explorador de Windows posicionándose directamente sobre el archivo encontrado.

### 5. 🧹 Limpiador Seguro de Temporales
- **Análisis Previo**: Calcula con exactitud cuántos GB puedes recuperar antes de borrar.
- **Categorías Limpiadas**:
  - Archivos temporales de usuario (`%TEMP%`)
  - Archivos temporales del sistema (`C:\Windows\Temp`)
  - Volcados de fallo de aplicaciones (`CrashDumps`, causantes de caídas drásticas de espacio)
  - Informes de error de Windows (WER)
  - Caché de descargas residuales de Windows Update
  - Caché de sombreadores DirectX (`D3DSCache`)
  - Vaciar Papelera de reciclaje (opcional con casilla)
- **Protección Antifallos**: Omite silenciosamente archivos bloqueados o en uso por aplicaciones abiertas sin congelar la app.

### 6. 🐍 Gestor de Entornos Virtuales (Venvs)
- **Detección Automática**: Localiza entornos virtuales (`venv`, `.venv`, `conda`) en `C:\Repositorios` y carpetas de proyectos del usuario.
- **Métricas Clave**: Calcula el peso exacto en MB/GB de cada entorno, versión de Python utilizada y fecha de última modificación.
- **Eliminación Individual o en Lote**: Selección múltiple con casillas para eliminar de golpe entornos obsoletos, o botón individual de eliminación con confirmación.
- **Protección de la App**: Protege de forma automática el entorno virtual en uso por esta aplicación para evitar borrados accidentales.

### 7. ⚠️ Monitor de Procesos Peligrosos y Sospechosos
- **Detección de Suplantación (Masquerading)**: Alerta si procesos con nombres de sistema (`svchost.exe`, `csrss.exe`, `lsass.exe`, `explorer.exe`) se ejecutan fuera de `System32`.
- **Rutas de Riesgo**: Detecta ejecutables corriendo directamente desde carpetas temporales (`%TEMP%`).
- **Comandos Ofuscados**: Identifica llamadas a PowerShell codificadas en base64 o descargas remotas no autorizadas.
- **Mineros de Criptomonedas**: Detecta patrones y ejecutables de minería (`xmrig`, `minerd`, etc.).
- **Gestión Inmediata**: Botón para forzar el cierre (`Finalizar Proceso`) y abrir la carpeta del binario en el Explorador.

### 8. 📡 Detección de Fuga de Datos & Tráfico Espía (Anti-Exfiltración)
- **Inspección de Conexiones Salientes en Tiempo Real**: Audita sockets **TCP y UDP** activos hacia internet vinculándolos con su proceso emisor exacto (`.exe`, PID, memoria y ruta). Detecta exfiltración por **DNS (UDP 53)** a servidores públicos desconocidos, **hostnames con patrón DGA**, y conexiones a dominios de exfiltración conocidos (C2 / webhooks / hosting), además de **SMB (445)** saliente.
- **Abuso de Procesos del Sistema (LOLBins)**: Alerta si herramientas como `powershell.exe`, `cmd.exe`, `rundll32.exe` o `certutil.exe` están comunicándose directamente hacia una IP pública externa.
- **Canales de Exfiltración Habituales**: Detección de conexiones no oficiales a APIs de bots de Telegram o Webhooks de Discord (técnica de InfoStealers como RedLine, Lumma o AgentTesla).
- **Puertos de Malware y RATs**: Identificación de tráfico saliente hacia puertos típicos de backdoors y troyanos (1337, 4444, 5555, 6667, 8888, etc.).
- **Alerta de Acceso a Credenciales**: Detección de procesos no autorizados accediendo a bases de datos de contraseñas de navegadores (Chrome/Edge/Firefox) o carteras cripto.
- **Botón "🛑 Cortar Conexión"**: Finaliza inmediatamente el proceso espía para cerrar el socket e impedir la subida de datos sensibles.

### 8.1. 🔒 Detección de Cifrado Activo (Ransomware)
- **Entropía de Shannon**: Mide la aleatoriedad de los archivos. Un documento es ~4.5 bits/byte; un archivo cifrado es ~7.7–7.99 bits/byte.
- **Extensiones de Ransomware**: Detecta extensiones de familias conocidas (LockBit, Conti, Royal, Magma, Babel, Akira, Petya, Nox, Ransack, Shadow, Nohome…).
- **Modificación Masiva**: Detecta carpetas donde muchos archivos son modificados en pocos minutos (el cifrador corre en bucle).
- **Tasa de Creación Anómala**: Detecta ráfagas de creación de archivos (borradas de datos nuevos).
- **Pestaña "🔒 Ransomware & Archivos"**: Analiza con ventana configurable (5–120 min), muestra archivos señalados con su entropía y permite abrirlos.

### 8.2. 📌 Baseline de Integridad (FIM)
- **Genera baseline** de hashes SHA-256 de tus carpetas (Desktop, Documents, Downloads, Pictures, Videos, Music, y la carpeta de la app).
- **Verifica** la baseline: detecta archivos **MODIFICADOS**, **ELIMINADOS** o **NUEVOS** (huella de un cifrador/ataque).
- **Monitorización continua**: Hilo en segundo plano que comprueba la tasa de creación/modificación y el estado de Defender cada X minutos (5–30 min), con alerta y log.
- **Exportación de reporte**: Guarda un JSON con todos los resultados (ransomware, integridad, hidratación, log) en `%APPDATA%\NetShield\Reports\`.

### 8.3. 🛡️ Hidratación & Persistencia del Sistema
- **Defender**: Estado de protección en tiempo real, si está deshabilitado (por registro o política).
- **Windows Update**: Parches pendientes de seguridad (alerta si hay muchos).
- **SMB (445)**: Si SMB está escuchando y parámetros del servidor (SMB sin firma permite SMB Relay / pass-the-hash en red local).
- **Persistencia**: Run keys (HKCU/HKLM, vistas 32/64), carpeta Startup, servicios no-Windows en ejecución, tareas programadas, y **WMI event consumers** (técnica de persistencia de atacantes).
- **Pestaña "🛡️ Hidratación & Sistema"**: Estado global (SEGURO/ADVERTENCIA/CRÍTICO) + detalle de cada mecanismo.

### 9. 📖 Centro de Ayuda & Guía del Usuario
- **Documentación Integrada e Interactiva**: Sección dedicada en la barra lateral con la explicación completa de cada uno de los 10 módulos de la aplicación.
- **Detalle Estructurado por Sección**:
  - 🎯 **Objetivo**: Propósito del módulo y qué problema resuelve.
  - ⚙️ **Cómo Funciona & Qué Analiza**: Llamadas al sistema (Win32 API, netsh, SendARP, Shannon entropy, etc.) y métricas analizadas.
  - 📋 **Modo de Uso Paso a Paso**: Instrucciones claras de qué botones pulsar y cómo interactuar.
  - 🚦 **Interpretación de Estados & Alertas**: Significado de semáforos verde/amarillo/rojo y umbrales.
  - 💡 **Recomendación**: Consejos de seguridad y buenas prácticas de mantenimiento.
- **Buscador en Tiempo Real**: Campo de búsqueda que filtra dinámicamente las tarjetas según palabras clave (ej. *dns*, *wifi*, *ransomware*, *temporales*, *puertos*, *svchost*).
- **Filtro por Áreas**: Botones segmentados para filtrar entre *Redes & Wi-Fi*, *Seguridad & Amenazas*, *Disco & Sistema* o *Guía Rápida*.
- **Navegación Directa**: Cada tarjeta incluye el botón **"🚀 Abrir Sección"** para saltar directamente a la funcionalidad deseada con un solo clic.

---

## 📂 Estructura del Proyecto

```
maintnance/
├── core/
│   ├── oui_database.py          # Base de datos OUI de fabricantes MAC
│   ├── wifi_analyzer.py         # Análisis de Wi-Fi, señal y red
│   ├── network_scanner.py       # Escaneo ARP multihilo de dispositivos LAN
│   ├── security_auditor.py      # Detección de ARP spoofing, DNS (multi-dominio) y puertos
│   ├── data_leak_detector.py    # Fuga de datos (TCP/UDP, DNS, C2, SMB, DGA)
│   ├── disk_tracker.py          # Rastreo de archivos creados en 7 días
│   ├── temp_cleaner.py          # Limpiador seguro de temporales y dumps
│   ├── venv_manager.py          # Gestor y limpiador de entornos virtuales
│   ├── process_auditor.py       # Auditor de procesos activos sospechosos
│   ├── ransomware_detector.py   # Cifrado activo (entropía, extensión, masiva)
│   ├── integrity_monitor.py     # Baseline de integridad (SHA-256) + verificación
│   └── system_harden.py         # Defender, parches, persistencia, SMB
├── gui/
│   └── app.py                   # Interfaz gráfica moderna (CustomTkinter)
├── dist/
│   └── NetShieldPro.exe         # Ejecutable independiente standalone
├── build_exe.bat                # Compilador automático a .exe
├── iniciar_herramienta.bat      # Lanzador directo para Windows
├── run.bat                      # Acceso rápido
└── requirements.txt             # Dependencias
```

---

## 🛠️ Requisitos Técnicos
- Windows 10 u 11 (64-bit).
- Python 3.10 o superior (verificado en Python 3.14).
