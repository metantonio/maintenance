"""
Módulo de Detección de Fuga de Datos, Exfiltración y Tráfico Espía (Data Leak & Spyware Detector).
Inspecciona conexiones de red salientes en tiempo real hacia internet para identificar si
algún programa espía, infostealer, troyano o proceso sospechoso está transmitiendo datos sensibles.
"""

import os
import re
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set
import psutil


class DataLeakDetector:
    """Motor de detección de exfiltración de datos sensibles y tráfico espía en Windows."""

    # Binarios legítimos de Windows comúnmente abusados por atacantes para exfiltrar datos (LOLBins)
    ABUSED_LOLBINS = {
        "powershell.exe": "PowerShell transmitiendo directamente hacia una IP pública (típico de reverse shell o script de exfiltración)",
        "pwsh.exe": "PowerShell Core comunicándose con el exterior",
        "cmd.exe": "Símbolo del sistema con socket TCP saliente a internet",
        "rundll32.exe": "rundll32 ejecutando DLL con conexión remota (técnica común de troyanos)",
        "certutil.exe": "certutil con conexión externa activa (frecuente en descargas/envíos ocultos)",
        "bitsadmin.exe": "bitsadmin con transferencia activa a internet",
        "mshta.exe": "mshta ejecutando scripts HTML con conexión remota",
        "cscript.exe": "Intérprete VBScript/JScript transmitiendo datos al exterior",
        "wscript.exe": "Intérprete de scripts de Windows con socket remoto abierto",
        "regsvr32.exe": "regsvr32 con comunicación externa (evasión de defensas)",
        "curl.exe": "curl enviando o descargando datos en segundo plano",
        "wget.exe": "wget transmitiendo al exterior"
    }

    # Procesos críticos del sistema cuya presencia fuera de System32 indica suplantación
    SYSTEM_CRITICAL_NAMES = {
        "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
        "smss.exe", "winlogon.exe", "wininit.exe", "taskhostw.exe",
        "dwm.exe", "lsaiso.exe", "sihost.exe", "explorer.exe"
    }

    # Puertos habituales de troyanos de acceso remoto (RAT) y backdoors
    KNOWN_SPY_PORTS = {
        1337: "Backdoor / RAT de control remoto",
        31337: "Back Orifice / Trojan",
        4444: "Metasploit C2 / Listener",
        5555: "Backdoor / ADB no seguro",
        6666: "IRC Botnet C2",
        6667: "IRC Botnet C2",
        8888: "Proxy / C2 no estándar",
        9999: "Backdoor Listener"
    }

    # Aplicaciones comunes legítimas conocidas de navegación o desarrollo
    KNOWN_TRUSTED_EXES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "discord.exe", "telegram.exe", "whatsapp.exe", "slack.exe", "teams.exe",
        "spotify.exe", "steam.exe", "epicgameslauncher.exe", "onedrive.exe",
        "dropbox.exe", "code.exe", "antigravity ide.exe", "cursor.exe",
        "language_server_windows_x64.exe", "pycharm64.exe", "git.exe",
        "anydesk.exe", "teamviewer.exe"
    }

    # Rutas sensibles de credenciales y carteras que el malware suele abrir antes de exfiltrar
    SENSITIVE_TARGET_FILES = [
        r"google\chrome\user data",
        r"microsoft\edge\user data",
        r"brave-browser\user data",
        r"mozilla\firefox\profiles",
        r"electrum\wallets",
        r"exodus\exodus.wallet",
        r"atomic wallet",
        r"appdata\roaming\telegram desktop\tdata"
    ]

    def __init__(self):
        self.system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
        self.system32 = os.path.join(self.system_root, "system32").lower()
        self.syswow64 = os.path.join(self.system_root, "syswow64").lower()
        self.temp_dir = os.environ.get("TEMP", "").lower()
        self.local_temp = os.path.join(os.environ.get("LOCALAPPDATA", ""), "temp").lower()
        self.appdata_local = os.environ.get("LOCALAPPDATA", "").lower()
        self.appdata_roaming = os.environ.get("APPDATA", "").lower()

        # Caché persistente de resoluciones DNS inversas
        self._dns_cache: Dict[str, str] = {}

    def is_private_or_local_ip(self, ip_str: str) -> bool:
        """Determina si una dirección IP es local, privada, de bucle invertido o multidifusión."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_multicast or
                ip.is_reserved or
                ip.is_link_local or
                ip_str.startswith("0.") or
                ip_str == "::" or
                ip_str == "::1"
            )
        except Exception:
            return True

    def resolve_remote_hosts_parallel(self, ips: List[str]) -> Dict[str, str]:
        """Resuelve en paralelo un lote de IPs remotas con tiempo límite estricto de 0.6s."""
        unique_ips = [ip for ip in set(ips) if ip not in self._dns_cache]

        def _lookup(ip: str):
            try:
                name, _, _ = socket.gethostbyaddr(ip)
                return ip, name
            except Exception:
                return ip, ip

        if unique_ips:
            max_workers = min(30, len(unique_ips))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_lookup, ip): ip for ip in unique_ips}
                for f in as_completed(futures):
                    try:
                        ip, host = f.result(timeout=0.6)
                        self._dns_cache[ip] = host
                    except Exception:
                        ip = futures[f]
                        self._dns_cache[ip] = ip

        return {ip: self._dns_cache.get(ip, ip) for ip in ips}

    def check_process_sensitive_files(self, p: psutil.Process) -> List[str]:
        """Inspecciona si un proceso específico tiene abiertos archivos sensibles de credenciales o wallets."""
        suspicious_opened = []
        try:
            for of in p.open_files():
                path_lower = of.path.lower()
                for sensitive in self.SENSITIVE_TARGET_FILES:
                    if sensitive in path_lower:
                        suspicious_opened.append(of.path)
                        break
        except Exception:
            pass
        return suspicious_opened

    def audit_outbound_transmissions(self) -> Dict[str, Any]:
        """
        Audita exhaustivamente todas las conexiones salientes activas hacia internet.
        Analiza cada proceso emisor, destino, tasa y calcula si hay fuga de datos o actividad espía.
        """
        transmissions: List[Dict[str, Any]] = []
        critical_count = 0
        warning_count = 0
        normal_count = 0

        # Obtener todas las conexiones inet
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception:
            connections = []

        # Filtrar solo conexiones establecidas o activas hacia el exterior
        valid_conns = []
        remote_ips_to_resolve = []
        for conn in connections:
            if conn.status in ('ESTABLISHED', 'SYN_SENT'):
                if conn.raddr:
                    r_ip = conn.raddr.ip
                    if not self.is_private_or_local_ip(r_ip):
                        valid_conns.append(conn)
                        remote_ips_to_resolve.append(r_ip)

        # Resolver todas las IPs en paralelo ultra rápido
        resolved_hosts = self.resolve_remote_hosts_parallel(remote_ips_to_resolve)

        # Agrupar conexiones por PID
        pid_conns: Dict[int, List[Any]] = {}
        for conn in valid_conns:
            pid = conn.pid or 0
            pid_conns.setdefault(pid, []).append(conn)

        # Analizar cada proceso con conexiones salientes
        for pid, conns in pid_conns.items():
            proc_name = "Desconocido"
            proc_exe = ""
            cmdline = ""
            username = "N/A"
            mem_mb = 0.0
            cpu = 0.0
            bytes_sent = 0
            ps_proc = None

            if pid > 0:
                try:
                    ps_proc = psutil.Process(pid)
                    proc_name = ps_proc.name()
                    proc_exe = ps_proc.exe() or ""
                    cmd_list = ps_proc.cmdline() or []
                    cmdline = " ".join(cmd_list)
                    username = ps_proc.username() or "N/A"
                    mem_mb = round((ps_proc.memory_info().rss / (1024 * 1024)), 1)
                    cpu = ps_proc.cpu_percent()

                    try:
                        io_counters = ps_proc.io_counters()
                        bytes_sent = io_counters.write_bytes
                    except Exception:
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

            name_lower = proc_name.lower()
            exe_lower = proc_exe.lower()

            # Comprobar acceso a archivos sensibles de credenciales si no es navegador legítimo
            opened_sensitive = []
            if ps_proc and name_lower not in ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"):
                opened_sensitive = self.check_process_sensitive_files(ps_proc)

            for conn in conns:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                state = conn.status

                remote_host = resolved_hosts.get(remote_ip, remote_ip)
                host_lower = remote_host.lower()

                # Evaluación de Amenaza y Fuga de Datos
                risk_level = "NORMAL"
                risk_color = "#38bdf8"
                reasons = []

                # REGLA 1: Abuso de LOLBins (PowerShell, cmd, certutil comunicándose a internet)
                if name_lower in self.ABUSED_LOLBINS:
                    risk_level = "CRÍTICO"
                    risk_color = "#ef4444"
                    reasons.append(f"¡LOLBin detectado! {self.ABUSED_LOLBINS[name_lower]}")

                # REGLA 2: Suplantación de Procesos del Sistema (Masquerading)
                if name_lower in self.SYSTEM_CRITICAL_NAMES:
                    if exe_lower and not exe_lower.startswith(self.system32) and not exe_lower.startswith(self.syswow64):
                        if not (name_lower == "explorer.exe" and exe_lower == os.path.join(self.system_root, "explorer.exe").lower()):
                            risk_level = "CRÍTICO"
                            risk_color = "#ef4444"
                            reasons.append(
                                f"Suplantación Crítica: Proceso con nombre de sistema '{proc_name}' "
                                f"ejecutándose fuera de System32 ({proc_exe}) transmitiendo al exterior."
                            )

                # REGLA 3: Ejecución desde carpetas de riesgo (Temp, Roaming oculta, Downloads)
                if exe_lower:
                    if "\\temp\\" in exe_lower or "\\appdata\\local\\temp\\" in exe_lower:
                        risk_level = "CRÍTICO"
                        risk_color = "#ef4444"
                        reasons.append("Transmisión de datos originada desde un archivo en carpeta Temporal (%TEMP%). Típico de spyware.")
                    elif "\\downloads\\" in exe_lower or "\\descargas\\" in exe_lower:
                        if risk_level != "CRÍTICO":
                            risk_level = "SOSPECHOSO"
                            risk_color = "#f59e0b"
                        reasons.append("El programa emisor está ejecutándose directamente desde la carpeta de Descargas.")

                # REGLA 4: Exfiltración hacia canales de mensajería (Telegram / Discord) por apps no oficiales
                is_telegram_target = "telegram" in host_lower or remote_ip.startswith("149.154.") or remote_ip.startswith("91.108.")
                if is_telegram_target and name_lower not in ("telegram.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"):
                    risk_level = "CRÍTICO"
                    risk_color = "#ef4444"
                    reasons.append(
                        f"¡ALERTA DE EXFILTRACIÓN! Proceso no oficial '{proc_name}' conectado a servidores de Telegram. "
                        "Patrón de robo de contraseñas de InfoStealers (RedLine/Lumma/AgentTesla)."
                    )

                is_discord_target = "discord" in host_lower
                if is_discord_target and name_lower not in ("discord.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"):
                    risk_level = "CRÍTICO"
                    risk_color = "#ef4444"
                    reasons.append(
                        f"Conexión a Discord Webhook/Servidor por el proceso '{proc_name}'. "
                        "Utilizado frecuentemente por troyanos para recibir datos robados."
                    )

                # REGLA 5: Puertos de Malware / RATs / Backdoors conocidos
                if remote_port in self.KNOWN_SPY_PORTS:
                    risk_level = "CRÍTICO"
                    risk_color = "#ef4444"
                    reasons.append(
                        f"Puerto de destino {remote_port} fuertemente vinculado a {self.KNOWN_SPY_PORTS[remote_port]}."
                    )

                # REGLA 6: Acceso activo a archivos de credenciales o carteras
                if opened_sensitive:
                    risk_level = "CRÍTICO"
                    risk_color = "#ef4444"
                    reasons.append(
                        f"¡ROBO DE IDENTIDAD DETECTADO! Este proceso tiene abiertos almacenes de contraseñas o carteras: {', '.join(opened_sensitive[:2])}"
                    )

                # REGLA 7: Proceso no identificado en AppData comunicándose con el exterior
                if name_lower not in self.KNOWN_TRUSTED_EXES and risk_level == "NORMAL":
                    if "\\appdata\\" in exe_lower and not any(k in exe_lower for k in ("google", "microsoft", "mozilla", "bravesoftware", "discord", "spotify", "vscode")):
                        risk_level = "SOSPECHOSO"
                        risk_color = "#f59e0b"
                        reasons.append(f"Proceso no estándar ejecutándose desde AppData comunicándose con {remote_ip}:{remote_port}.")

                # REGLA 8: Tráfico en texto plano no cifrado (Puerto 80 HTTP) desde apps no web ni sistema
                if remote_port == 80 and name_lower not in self.KNOWN_TRUSTED_EXES and name_lower != "svchost.exe":
                    if risk_level == "NORMAL":
                        risk_level = "SOSPECHOSO"
                        risk_color = "#f59e0b"
                    reasons.append(f"Transmisión HTTP sin cifrar (puerto 80) hacia {remote_ip}. Los datos viajan en texto plano.")

                # Contabilizar
                if risk_level == "CRÍTICO":
                    critical_count += 1
                elif risk_level == "SOSPECHOSO":
                    warning_count += 1
                else:
                    normal_count += 1

                transmissions.append({
                    "pid": pid,
                    "process_name": proc_name,
                    "exe": proc_exe,
                    "cmdline": cmdline,
                    "username": username,
                    "memory_mb": mem_mb,
                    "cpu_percent": cpu,
                    "bytes_sent": bytes_sent,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "remote_host": remote_host,
                    "connection_state": state,
                    "risk_level": risk_level,
                    "risk_color": risk_color,
                    "reasons": reasons,
                    "is_dangerous": (risk_level == "CRÍTICO"),
                    "is_suspicious": (risk_level in ("CRÍTICO", "SOSPECHOSO"))
                })

        # Ordenar transmisiones: primero Críticos, luego Sospechosos, luego Normales
        def sort_key(item):
            lvl = item["risk_level"]
            score = 3 if lvl == "CRÍTICO" else (2 if lvl == "SOSPECHOSO" else 1)
            return (score, item["pid"])

        transmissions.sort(key=sort_key, reverse=True)

        # Determinar estado global
        if critical_count > 0:
            status_text = "🚨 ALTO RIESGO: Posible Exfiltración de Datos Detectada"
            status_color = "#ef4444"
            summary_desc = (
                f"Se han detectado {critical_count} transmisiones con indicios críticos de programa espía "
                "(comunicación hacia servidores de exfiltración, abuso de procesos del sistema o ejecución desde rutas temporales)."
            )
        elif warning_count > 0:
            status_text = "⚠️ ATENCIÓN: Conexiones Sospechosas en Curso"
            status_color = "#f59e0b"
            summary_desc = (
                f"Hay {warning_count} conexiones salientes desde procesos no estándar o puertos inusuales que requieren verificación."
            )
        else:
            status_text = "✅ SEGURO: Sin Indicios de Transmisión Espía Activa"
            status_color = "#00C851"
            summary_desc = (
                f"Todas las {len(transmissions)} conexiones salientes hacia internet provienen de navegadores o aplicaciones reconocidas. "
                "No hay indicios de exfiltración ni robo de datos en curso."
            )

        recommendations = []
        if critical_count > 0:
            recommendations.append("Finaliza inmediatamente los procesos marcados en rojo utilizando el botón '🛑 Cortar Conexión'.")
            recommendations.append("Desconecta temporalmente el equipo de internet si sospechas de una infección activa para evitar que sigan subiendo datos.")
            recommendations.append("Cambia las contraseñas de tus cuentas principales (Google, banca, redes) desde otro dispositivo de confianza.")
        elif warning_count > 0:
            recommendations.append("Revisa los procesos marcados en naranja y su ruta en disco para asegurarte de que son programas que tú instalaste deliberadamente.")

        return {
            "status_text": status_text,
            "status_color": status_color,
            "summary_desc": summary_desc,
            "critical_count": critical_count,
            "warning_count": warning_count,
            "normal_count": normal_count,
            "total_transmissions": len(transmissions),
            "transmissions": transmissions,
            "recommendations": recommendations
        }

    def kill_process(self, pid: int) -> Dict[str, Any]:
        """Termina forzosamente el proceso espía para cortar de raíz la transmisión de datos."""
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            p.terminate()
            try:
                p.wait(timeout=2)
            except psutil.TimeoutExpired:
                p.kill()

            return {
                "success": True,
                "message": f"Conexión cortada con éxito. Proceso '{p_name}' (PID: {pid}) finalizado."
            }
        except psutil.NoSuchProcess:
            return {"success": True, "message": "El proceso emisor ya no se encuentra en ejecución."}
        except psutil.AccessDenied:
            return {
                "success": False,
                "message": "Permiso denegado. Se requieren privilegios de Administrador para finalizar este proceso."
            }
        except Exception as e:
            return {"success": False, "message": f"Error al finalizar proceso: {str(e)}"}

    def open_process_folder(self, exe_path: str) -> bool:
        """Abre la carpeta que aloja el ejecutable en el Explorador de Windows."""
        try:
            if exe_path and os.path.exists(exe_path):
                subprocess.Popen(f'explorer.exe /select,"{os.path.normpath(exe_path)}"')
                return True
        except Exception:
            pass
        return False
