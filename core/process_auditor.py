"""
Módulo de Auditoría y Detección de Procesos Activos Peligrosos o Sospechosos.
Inspecciona los procesos en ejecución analizando suplantaciones (masquerading),
ejecución desde rutas de riesgo, comandos ofuscados, mineros y conexiones no autorizadas.
"""

import os
import subprocess
from typing import List, Dict, Any, Optional
import psutil


class ProcessAuditor:
    """Auditor de procesos activos para identificar amenazas y procesos sospechosos."""

    SYSTEM_CRITICAL_NAMES = {
        "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
        "smss.exe", "winlogon.exe", "wininit.exe", "taskhostw.exe",
        "dwm.exe", "lsaiso.exe", "sihost.exe"
    }

    KNOWN_MINER_KEYWORDS = {
        "xmrig", "minerd", "ethminer", "phoenixminer", "nbminer",
        "t-rex", "gminer", "nanominer", "teamredminer", "lolminer"
    }

    SUSPICIOUS_CMD_KEYWORDS = [
        "-enc", "-encodedcommand", "downloadstring", "invoke-expression",
        "iex(", "bypass", "windowstyle hidden", "curl http", "wget http",
        "certutil -urlcache", "bitsadmin /transfer"
    ]

    def __init__(self):
        self.system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()
        self.system32 = os.path.join(self.system_root, "system32").lower()
        self.syswow64 = os.path.join(self.system_root, "syswow64").lower()
        self.temp_dir = os.environ.get("TEMP", "").lower()
        self.local_temp = os.path.join(os.environ.get("LOCALAPPDATA", ""), "temp").lower()

    def scan_running_processes(self) -> List[Dict[str, Any]]:
        """
        Escanea todos los procesos del sistema y los clasifica según su nivel de riesgo:
        PELIGRO, SOSPECHOSO o NORMAL.
        """
        results = []

        # Primera pasada para medir CPU porcentual
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_info', 'create_time', 'username']):
            try:
                info = p.info
                pid = info.get("pid")
                name = info.get("name") or "Desconocido"
                exe = info.get("exe") or ""
                cmdline_list = info.get("cmdline") or []
                cmdline_str = " ".join(cmdline_list)
                mem_mb = round((info.get("memory_info").rss / (1024 * 1024)), 1) if info.get("memory_info") else 0.0
                cpu = info.get("cpu_percent") or 0.0

                name_lower = name.lower()
                exe_lower = exe.lower()
                cmd_lower = cmdline_str.lower()

                risk_level = "NORMAL"
                risk_color = "#38bdf8"
                reasons = []

                # 1. Regla: Suplantación de proceso del sistema (Masquerading)
                if name_lower in self.SYSTEM_CRITICAL_NAMES:
                    if exe_lower and not exe_lower.startswith(self.system32) and not exe_lower.startswith(self.syswow64):
                        risk_level = "PELIGRO"
                        risk_color = "#ef4444"
                        reasons.append(
                            f"Suplantación crítica: Proceso con nombre de sistema '{name}' ejecutándose fuera de System32 ({exe})."
                        )

                # Especial para explorer.exe
                if name_lower == "explorer.exe" and exe_lower:
                    valid_explorer = os.path.join(self.system_root, "explorer.exe").lower()
                    if exe_lower != valid_explorer:
                        risk_level = "PELIGRO"
                        risk_color = "#ef4444"
                        reasons.append(f"explorer.exe falso ejecutándose desde una ruta no autorizada ({exe}).")

                # 2. Regla: Ejecución desde carpetas temporales (típico de virus / droppers)
                if exe_lower and ("\\temp\\" in exe_lower or "\\appdata\\local\\temp\\" in exe_lower):
                    if risk_level != "PELIGRO":
                        risk_level = "SOSPECHOSO"
                        risk_color = "#f59e0b"
                    reasons.append("El ejecutable está corriendo directamente desde una carpeta temporal (Temp).")

                # 3. Regla: Comandos ofuscados o PowerShell sospechoso
                for kw in self.SUSPICIOUS_CMD_KEYWORDS:
                    if kw in cmd_lower:
                        risk_level = "PELIGRO"
                        risk_color = "#ef4444"
                        reasons.append(f"Línea de comando con patrón de ataque o ejecución oculta: '{kw}' detectado.")
                        break

                # 4. Regla: Minería de criptomonedas
                for miner_kw in self.KNOWN_MINER_KEYWORDS:
                    if miner_kw in name_lower or miner_kw in cmd_lower:
                        risk_level = "PELIGRO"
                        risk_color = "#ef4444"
                        reasons.append(f"Coincidencia con software de minería de criptomonedas ({miner_kw}).")
                        break

                # 5. Regla: Consumo anómalo de CPU sin archivo identificado
                if cpu > 70.0 and not exe:
                    if risk_level == "NORMAL":
                        risk_level = "SOSPECHOSO"
                        risk_color = "#f59e0b"
                    reasons.append(f"Alto consumo de CPU ({cpu}%) sin ejecutable identificable en disco.")

                entry = {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline_str,
                    "cpu_percent": cpu,
                    "memory_mb": mem_mb,
                    "username": info.get("username") or "N/A",
                    "risk_level": risk_level,
                    "risk_color": risk_color,
                    "reasons": reasons,
                    "is_suspicious": (risk_level in ("PELIGRO", "SOSPECHOSO"))
                }
                results.append(entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        # Ordenar: primero los de PELIGRO, luego SOSPECHOSOS, luego por consumo de memoria
        def sort_priority(item):
            lvl = item["risk_level"]
            score = 3 if lvl == "PELIGRO" else (2 if lvl == "SOSPECHOSO" else 1)
            return (score, item["memory_mb"])

        results.sort(key=sort_priority, reverse=True)
        return results

    def kill_process(self, pid: int) -> Dict[str, Any]:
        """Termina forzosamente un proceso por su PID."""
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            p.terminate()
            # Esperar hasta 2 segundos para cierre limpio, si no forzar kill
            try:
                p.wait(timeout=2)
            except psutil.TimeoutExpired:
                p.kill()

            return {
                "success": True,
                "message": f"Proceso '{p_name}' (PID: {pid}) finalizado con éxito."
            }
        except psutil.NoSuchProcess:
            return {"success": True, "message": "El proceso ya no se encuentra activo."}
        except psutil.AccessDenied:
            return {
                "success": False,
                "message": "Permiso denegado. Se requieren privilegios de Administrador para finalizar este proceso."
            }
        except Exception as e:
            return {"success": False, "message": f"Error al finalizar proceso: {str(e)}"}

    def open_process_folder(self, exe_path: str) -> bool:
        """Abre la carpeta del ejecutable en el Explorador de Windows."""
        try:
            if exe_path and os.path.exists(exe_path):
                subprocess.Popen(f'explorer.exe /select,"{os.path.normpath(exe_path)}"')
                return True
        except Exception:
            pass
        return False
