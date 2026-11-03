"""
Smoke tests para las nuevas funcionalidades de NetShield.
Ejecuta: venv\\Scripts\\python.exe test_netshield.py
"""
import os
import sys
import random
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0

def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name}  <-- {detail}")

print("=" * 60)
print("1) IMPORTS")
print("=" * 60)
check("import core", True)
from core.ransomware_detector import RansomwareDetector
from core.integrity_monitor import IntegrityMonitor
from core.system_harden import SystemHardener
from core.data_leak_detector import DataLeakDetector
from core.security_auditor import SecurityAuditor
check("import nuevos módulos", True)

print("\n2) RANSOMWARE DETECTOR")
print("=" * 60)
detector = RansomwareDetector()
check("constructor", detector is not None)
# Entropía
from core.ransomware_detector import _file_entropy, _shannon_entropy
check("función de entropía disponible", _file_entropy is not None and _shannon_entropy is not None)
# Generar un archivo cifrado simulado y probar detección
with tempfile.TemporaryDirectory() as td:
    # carpeta de trabajo
    workdir = os.path.join(td, "Documents")
    os.makedirs(workdir)
    # Archivo "cifrado": 5MB de bytes aleatorios con extensión lockbit
    fname = os.path.join(workdir, "foto.lockbit")
    with open(fname, "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))
    # Archivo normal (texto)
    fname2 = os.path.join(workdir, "nota.txt")
    with open(fname2, "w", encoding="utf-8") as f:
        f.write("hola mundo " * 100)
    # Archivo de extensión de ransomware (pequeño, aleatorio)
    fname3 = os.path.join(workdir, "doc.crypt")
    with open(fname3, "wb") as f:
        f.write(os.urandom(200 * 1024))
    # Forzar mtime a ahora (ya es ahora)
    result = detector.scan(base_paths=[workdir], window_min=15, min_size_bytes=100)
    check("detecta CRÍTICO", result["severity"] == "CRÍTICO", result["severity"])
    check("detecta extensiones ransomware",
           len(result["ransomware_ext_files"]) >= 2,
           f"{len(result['ransomware_ext_files'])} de 2")
    check("archivo normal txt no detectado por entropía",
           not any(x["name"] == "nota.txt" for x in result["high_entropy_files"]),
           "el txt fue flaggeado como high entropy")
    print(f"   severidad={result['severity']} ext_files={len(result['ransomware_ext_files'])} "
          f"high_entropy={len(result['high_entropy_files'])}")
    # Entropía de archivo normal baja
    ent_txt = _file_entropy(fname2)
    check("entropía texto baja (< 6)", ent_txt is not None and ent_txt < 6.0, f"entropía={ent_txt:.2f}")

print("\n3) INTEGRITY MONITOR")
print("=" * 60)
monitor = IntegrityMonitor(base_dir=os.path.join(tempfile.gettempdir(), "netshield-test"))
check("default config", monitor.default_config()["watched_paths"])
# Baseline en una carpeta de prueba
with tempfile.TemporaryDirectory() as td:
    base = os.path.join(td, "docs")
    os.makedirs(base)
    f1 = os.path.join(base, "a.txt")
    f2 = os.path.join(base, "b.txt")
    open(f1, "w", encoding="utf-8").write("contenido original")
    open(f2, "w", encoding="utf-8").write("otro contenido")
    gen = monitor.generate_baseline(watched_paths=[base])
    check("generar baseline ok", gen["success"] and gen["files_hashed"] == 2, gen)
    # Cambiar un archivo
    open(f1, "w", encoding="utf-8").write("CONTENIDO MODIFICADO!!!")
    # Borrar otro
    os.remove(f2)
    # Añadir uno nuevo
    open(f1 + ".nuevo", "w", encoding="utf-8").write("nuevo")
    ver = monitor.verify_baseline()
    check("verificación exitosa", ver["success"])
    check("detecta MODIFICADOS=1", len(ver["changed"]) == 1, ver["changed"])
    check("detecta ELIMINADOS=1", len(ver["deleted"]) == 1, ver["deleted"])
    check("detecta NUEVOS=1", len(ver["new_files"]) == 1, ver["new_files"])
    check("severidad CRÍTICO", ver["severity"] == "CRÍTICO")

print("\n4) SYSTEM HARDENER (Defender + Persistencia + SMB)")
print("=" * 60)
hardener = SystemHardener()
res = hardener.run_all()
check("run_all devuelve dict", isinstance(res, dict))
check("defender tiene status", res["defender"]["status"] in ("NORMAL", "ADVERTENCIA", "CRÍTICO"),
       res["defender"]["status"])
check("windows_update tiene status", res["windows_update"]["status"] in ("NORMAL", "ADVERTENCIA", "CRÍTICO"),
       res["windows_update"]["status"])
check("smb tiene status", res["smb"]["status"] in ("NORMAL", "ADVERTENCIA"),
       res["smb"]["status"])
check("persistence tiene issues", "issues" in res["persistence"])
defender = res["defender"]
print(f"   Defender={defender['status']} ({defender['message'][:60]})")
print(f"   WU={res['windows_update']['status']} pending={res['windows_update']['pending']}")
print(f"   SMB={res['smb']['status']} listening={res['smb']['listening']}")

print("\n5) DATA LEAK DETECTOR (UDP/DNS/C2/SMB/DGA)")
print("=" * 60)
dll = DataLeakDetector()
# Pruebas de DGA
check("DGA: x7k9m2q4z4.io (etiqueta larga con dígitos) es DGA", dll._is_dga_like("x7k9m2q4z4.io"))
check("DGA: google.com NO es DGA", not dll._is_dga_like("google.com"))
check("DGA: subdominio corto normal NO es DGA", not dll._is_dga_like("cdn.example.com"))
check("DGA: TLD con dígitos es DGA", dll._is_dga_like("api.xyz99.com"))
print("   KNOWN_SPY_PORTS tiene 445:", 445 in dll.KNOWN_SPY_PORTS)
print("   KNOWN_DNS_PROVIDERS:", len(dll.KNOWN_DNS_PROVIDERS))
print("   C2_DOMAINS:", len(dll.C2_DOMAINS))

print("\n6) SECURITY AUDITOR (DNS multi-dominio)")
print("=" * 60)
auditor = SecurityAuditor()
res = auditor.check_dns_hijacking()
check("check_dns_hijacking devuelve dict", isinstance(res, dict))
check("prueba multi-dominio", len(res["test_domains"]) >= 2, res["test_domains"])
print(f"   severidad={res['severity']}")
# Prueba _is_private_ip
check("_is_private_ip 192.168.1.1", auditor._is_private_ip("192.168.1.1"))
check("_is_private_ip 10.0.0.1", auditor._is_private_ip("10.0.0.1"))
check("_is_private_ip 172.16.0.1", auditor._is_private_ip("172.16.0.1"))
check("_is_private_ip 8.8.8.8 NO (es público)", not auditor._is_private_ip("8.8.8.8"))
check("_is_private_ip 169.254.1.1 (link-local)", auditor._is_private_ip("169.254.1.1"))

print("\n7) GUI (import y estructura)")
print("=" * 60)
try:
    import tkinter
    print("   tkinter disponible")
    # No creamos la GUI (necesita display), solo comprobamos que la clase existe
    import importlib
    gui_mod = importlib.import_module("gui.app")
    check("gui.app importado", gui_mod is not None)
    check("ModernApp tiene _create_ransomware_view", hasattr(gui_mod.ModernApp, "_create_ransomware_view"))
    check("ModernApp tiene _create_hardening_view", hasattr(gui_mod.ModernApp, "_create_hardening_view"))
    check("ModernApp tiene _export_report", hasattr(gui_mod.ModernApp, "_export_report"))
except Exception as e:
    check("gui.app importado", False, str(e))

print("\n" + "=" * 60)
print(f"RESUMEN: {PASS} OK, {FAIL} FALLIDOS")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
