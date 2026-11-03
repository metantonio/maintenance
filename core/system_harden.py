"""
Hidratación del sistema y auditoría de persistencia.

Módulo de defensa proactiva contra virus, hackers, ransomware y ataques
externos. Comprueba:

  * Estado de las defensas de Windows (Defender, parches de seguridad)
  * Mecanismos de persistencia (arrancado: Run keys, Startup, Winlogon Shell;
    servicios desconocidos; tareas programadas; WMI event subscribers)
  * Exposición local de SMB (puerto 445 y parámetros del servidor)

Todo es de solo LECTURA: no modifica nada, solo informa.
"""

import csv
import io
import json
import os
import socket
import subprocess
import tempfile
import winreg
from datetime import datetime
from typing import Dict, Any, List, Optional

APP_NAME = "NetShield"


class SystemHardener:
    """Auditoría de hidratación y persistencia de Windows."""

    # Servicios que se consideran "normales" (por nombre)
    KNOWN_MS_SERVICES = {
        "svchost", "csrss", "lsass", "services", "smss", "winlogon",
        "wininit", "taskhostw", "dwm", "explorer", "services.exe",
        "system", "wininet", "wmi", "wmi", "wmiauto", "wmiauto",
    }

    def _run_ps_file(self, script: str, timeout: int = 20):
        """Ejecuta un script PowerShell en un archivo temporal."""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as f:
                f.write(script)
                tmp = f.name
            p = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp],
                capture_output=True, text=True, errors="ignore", timeout=timeout,
            )
        except Exception as e:
            return -1, "", str(e)
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
        return p.returncode, p.stdout, p.stderr

    def check_defender(self) -> Dict[str, Any]:
        """
        Estado de Windows Defender (línea de defensa #1).

        Devuelve: {status, message, details}
        """
        details = []

        # 1) Registro: Defender deshabilitado por DisableAntiSpyware
        reg_disabled = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows Defender") as k:
                val, typ = winreg.QueryValue(k, "DisableAntiSpyware")
                if val == 1:
                    reg_disabled = True
        except (FileNotFoundError, OSError):
            pass

        if reg_disabled:
            details.append("Defender deshabilitado por el registro (DisableAntiSpyware=1).")

        # 2) Get-MpComputerStatus
        script = """
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($null -eq $mp) {
    Write-Output "RT=NO AV=NO AVDP=NO AU=NO SIG=NO ENG=NO"
} else {
    Write-Output ("RT=" + $mp.RealTimeProtectionEnabled +
                  " AV=" + $mp.AntivirusEnabled +
                  " AVDP=" + $mp.AntivirusDisabledByPolicy +
                  " AU=" + $mp.AutomaticUpdatesEnabled +
                  " SIG=" + $mp.SignatureDatabaseVersion +
                  " ENG=" + $mp.EngineVersion)
}
"""
        rc, out, err = self._run_ps_file(script, 15)
        fields = {}
        for part in (out or "").strip().split():
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k] = v.upper()

        rt = fields.get("RT") == "TRUE"
        av = fields.get("AV") == "TRUE"
        avdp = fields.get("AVDP") == "TRUE"
        au = fields.get("AU") == "TRUE"
        sig = fields.get("SIG", "N/A")
        eng = fields.get("ENG", "N/A")

        if fields.get("RT") == "NO":
            status = "CRÍTICO"
            message = "Windows Defender NO está disponible en este equipo."
        elif reg_disabled or avdp:
            status = "CRÍTICO"
            message = "Defender está deshabilitado (por registro o por política)."
        elif not rt:
            status = "CRÍTICO"
            message = "Protección en tiempo real DESACTIVADA."
        elif not av:
            status = "CRÍTICO"
            message = "Antivirus deshabilitado."
        else:
            status = "NORMAL"
            if au:
                message = f"Defender activo (protección en tiempo real, " \
                          f"actualizaciones automáticas). Firma: {sig}."
            else:
                status = "ADVERTENCIA"
                message = f"Defender activo pero actualizaciones automáticas " \
                          f"DESACTIVADAS. Firma: {sig}."

        if fields.get("ENG") and fields.get("ENG") != "N/A":
            details.append(f"Motor Defender v{eng}")
        if fields.get("SIG") and fields.get("SIG") != "N/A":
            details.append(f"Firmas: {sig}")

        return {"status": status, "message": message, "details": details}

    def check_windows_update(self) -> Dict[str, Any]:
        """
        Estado de Windows Update (parches pendientes).

        Devuelve: {status, pending, last_update, message}
        """
        script = r"""
try {
    $u = New-Object -ComObject 'Microsoft.Update.Session'
    $su = $u.Searcher
    $r = $su.Search('IsInstalled=0 AND Type=''Software''')
    $pending = (@($r.Updates)).Count
    $last = (@($r.Updates) | Sort-Object -Property InstallDate -Descending | Select-Object -First 1)
    $lastDate = if ($last) { $last.InstallDate.ToString('yyyy-MM-dd') } else { 'N/A' }
    Write-Output ("PENDING=" + $pending + ";LAST=" + $lastDate)
} catch {
    Write-Output ("ERR=" + $_.Exception.Message)
}
"""
        rc, out, err = self._run_ps_file(script, 25)
        line = (out or "").strip()
        pending = 0
        last = "N/A"
        if line.startswith("PENDING="):
            rest = line[8:].split(";")
            pending = int(rest[0].strip()) if rest else 0
            last = rest[1] if len(rest) > 1 else "N/A"
        elif line.startswith("ERR="):
            return {
                "status": "ADVERTENCIA",
                "pending": None,
                "last_update": "N/A",
                "message": f"Error consultando Windows Update: {line[4:]}",
            }

        if pending and pending >= 10:
            status = "CRÍTICO"
            message = f"¡{pending} parche(s) de seguridad PENDIENTE(S)! El equipo está desactualizado."
        elif pending:
            status = "ADVERTENCIA"
            message = f"{pending} parche(s) de seguridad pendiente(s). Aplica actualizaciones."
        else:
            status = "NORMAL"
            message = "Sin parches pendientes. Sistema actualizado."

        return {
            "status": status,
            "pending": pending,
            "last_update": last,
            "message": message,
        }

    def _run_keys(self):
        """Yield (hive_name, subpath, value_name, value) de las Run keys."""
        hives = {
            winreg.HKEY_CURRENT_USER: "HKCU",
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
        }
        for hive, name in hives.items():
            for sub in (
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            ):
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        i = 0
                        while True:
                            try:
                                vname, value, typ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            yield name, sub, vname, value
                            i += 1
                except OSError:
                    continue

    def _startup_folder_files(self) -> List[str]:
        """Archivos en la carpeta Startup (lnk, exe, bat, cmd, ps1, vbs)."""
        files = []
        for base in (os.environ.get("APPDATA"), os.environ.get("ProgramData")):
            if not base:
                continue
            start = os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if not os.path.isdir(start):
                continue
            try:
                for f in os.listdir(start):
                    fp = os.path.join(start, f)
                    if os.path.isfile(fp):
                        files.append(fp)
            except OSError:
                pass
        return files

    def _services(self) -> List[Dict[str, Any]]:
        """Servicios en ejecución que NO están bajo C:\\Windows (sospechosos)."""
        suspicious = []
        script = r"""
Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Running' -and $_.PathName } |
    Select-Object -Property Name, PathName, StartMode |
    ConvertTo-Json -Compress
"""
        rc, out, err = self._run_ps_file(script, 15)
        if rc != 0 or not out or out.strip().lower() in ("null", "[]"):
            return suspicious
        try:
            services = json.loads(out.strip())
        except Exception:
            return suspicious
        for s in services:
            path = s.get("PathName", "").lower()
            if path and not path.startswith("c:\\windows"):
                suspicious.append({
                    "name": s.get("Name", ""),
                    "path": s.get("PathName", ""),
                    "start_mode": s.get("StartMode", ""),
                })
        return suspicious

    def _scheduled_tasks(self) -> List[Dict[str, str]]:
        """Tareas programadas (CSV). Filtra las no de Microsoft."""
        tasks = []
        try:
            p = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, errors="ignore", timeout=15,
            )
        except Exception:
            return tasks
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        if not lines:
            return tasks
        reader = csv.DictReader(io.StringIO("\r\n".join(lines)))
        for row in reader:
            if not row:
                continue
            name = row.get("TaskName", "")
            user = row.get("User", "")
            command = row.get("Command", "") or row.get("TaskName", "")
            args = row.get("Arguments", "") or ""
            # Omitir tareas de Windows estándar (Microsoft)
            if user and user.lower().startswith(("microsoft", "windows")):
                continue
            if not name:
                continue
            tasks.append({
                "name": name,
                "user": user,
                "command": command,
                "arguments": args,
            })
        return tasks

    def _wmi(self) -> Dict[str, Any]:
        """
        WMI event subscribers: filtros, consumidores y bindings.

        Los atacantes usan WMI para persistir y ejecutarte código sin dejar
        rastro en el registro normal (técnica de "WMI Persistence").
        """
        script = r"""
$f = Get-CimInstance -Namespace root/cimv2 -ClassName '__EventFilter' -ErrorAction SilentlyContinue
$c = Get-CimInstance -Namespace root/cimv2 -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
$b = Get-CimInstance -Namespace root/cimv2 -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
Write-Output ("FILTERS=" + (@($f).Count))
Write-Output ("CONSUMERS=" + (@($c).Count))
Write-Output ("BINDINGS=" + (@($b).Count))
$f | ForEach-Object { Write-Output ("F:" + $_.ID + "|" + $_.Query) }
$c | ForEach-Object { Write-Output ("C:" + $_.ID + "|" + $_.CommandLine) }
$b | ForEach-Object { Write-Output ("B:" + $_.Filter + "|" + $_.Consumer + "|" + $_.NamespaceName) }
"""
        rc, out, err = self._run_ps_file(script, 15)
        filters = []
        consumers = []
        bindings = []
        for line in (out or "").splitlines():
            if line.startswith("FILTERS="):
                continue
            elif line.startswith("CONSUMERS="):
                continue
            elif line.startswith("BINDINGS="):
                continue
            elif line.startswith("F:"):
                rest = line[2:]
                parts = rest.split("|", 1)
                filters.append({
                    "id": parts[0],
                    "query": parts[1] if len(parts) > 1 else "",
                })
            elif line.startswith("C:"):
                rest = line[2:]
                parts = rest.split("|", 1)
                consumers.append({
                    "id": parts[0],
                    "command_line": parts[1] if len(parts) > 1 else "",
                })
            elif line.startswith("B:"):
                rest = line[2:]
                parts = rest.split("|", 2)
                bindings.append({
                    "filter": parts[0],
                    "consumer": parts[1],
                    "namespace": parts[2] if len(parts) > 2 else "",
                })
        return {"filters": filters, "consumers": consumers, "bindings": bindings}

    def check_smb(self) -> Dict[str, Any]:
        """
        Exposición local de SMB (puerto 445 y parámetros del servidor).

        SMB sin firma permite que un atacante local haga SMB Relay / pass-the-hash.
        """
        listening = False
        try:
            with socket.create_connection(("127.0.0.1", 445), timeout=2):
                listening = True
        except Exception:
            listening = False

        # Parámetros del servidor SMB
        params: Dict[str, int] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as k:
                i = 0
                while True:
                    try:
                        name, value, typ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    # Solo DWORDs
                    if typ == winreg.REG_DWORD:
                        params[name] = value
                    i += 1
        except (FileNotFoundError, OSError):
            pass

        status = "NORMAL"
        if listening:
            status = "ADVERTENCIA"

        return {
            "listening": listening,
            "status": status,
            "params": params,
            "message": (
                "SMB (puerto 445) ESCUCHANDO localmente. "
                "Verifica que las carpetas compartidas son las que esperas. "
                "SMB sin firma permite ataques SMB Relay / pass-the-hash en la red local."
                if listening
                else "SMB (445) NO está escuchando. Sin exposición local activa."
            ),
        }

    def audit_persistence(self) -> Dict[str, Any]:
        """
        Auditoría completa de persistencia.

        Devuelve: {startup_entries, startup_folder_files, winlogon_shell,
                   services, scheduled_tasks, wmi, issues}
        """
        issues: List[str] = []

        # 1) Run keys
        startup_entries: List[Dict[str, str]] = []
        for name, sub, vname, value in self._run_keys():
            if value:
                entry = {"hive": name, "key": sub, "name": vname, "value": str(value)}
                startup_entries.append(entry)
                # Detectar ejecutables que no son de Windows
                low = str(value).lower()
                if low.startswith(("c:\\windows\\system32", "c:\\windows\\syswow64",
                                   "c:\\windows\\wsw", "wsw", "rundll32", "mshta")):
                    pass
                # No marcos como "issue" a los de Windows, solo listarlos
        issues.extend([f"{e['hive']}\\{e['key']}: {e['name']} -> {e['value'][:80]}"
                       for e in startup_entries if "c:\\windows" not in e["value"].lower()])

        # 2) Winlogon Shell
        winlogon_shell = "N/A"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon") as k:
                winlogon_shell, _ = winreg.QueryValue(k, "Shell")
        except Exception:
            pass
        if winlogon_shell.lower() != "c:\\windows\\explorer.exe":
            issues.append(f"Winlogon Shell modificado: {winlogon_shell}")

        # 3) Servicios
        services = self._services()

        # 4) Tareas programadas
        tasks = self._scheduled_tasks()

        # 5) WMI
        wmi = self._wmi()
        if wmi["filters"] or wmi["consumers"] or wmi["bindings"]:
            issues.append(
                f"Subscripciones WMI: {len(wmi['filters'])} filtros, "
                f"{len(wmi['consumers'])} consumidores, "
                f"{len(wmi['bindings'])} bindings"
            )

        # 6) Carpeta Startup
        startup_files = self._startup_folder_files()

        status = "ADVERTENCIA" if issues else "NORMAL"
        return {
            "startup_entries": startup_entries,
            "startup_folder_files": startup_files,
            "winlogon_shell": winlogon_shell,
            "services": services,
            "scheduled_tasks": tasks,
            "wmi": wmi,
            "issues": issues,
            "status": status,
        }

    def run_all(self) -> Dict[str, Any]:
        """Ejecuta todas las comprobaciones y devuelve un resumen."""
        defender = self.check_defender()
        wu = self.check_windows_update()
        smb = self.check_smb()
        persistence = self.audit_persistence()

        # Severidad global
        statuses = [defender["status"], wu["status"], smb["status"],
                    persistence["status"]]
        if "CRÍTICO" in statuses:
            global_status = "CRÍTICO"
        elif "ADVERTENCIA" in statuses:
            global_status = "ADVERTENCIA"
        else:
            global_status = "NORMAL"

        return {
            "global_status": global_status,
            "defender": defender,
            "windows_update": wu,
            "smb": smb,
            "persistence": persistence,
            "timestamp": datetime.now().isoformat(),
        }


if __name__ == "__main__":
    h = SystemHardener()
    res = h.run_all()
    print("Global:", res["global_status"])
    print("Defender:", res["defender"]["message"])
    print("Update:", res["windows_update"]["message"])
    print("SMB:", res["smb"]["message"])
    p = res["persistence"]
    print("Persistencia:", p["status"])
    print("Issues:", p["issues"])
