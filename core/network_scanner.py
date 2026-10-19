"""
Módulo de Escaneo y Descubrimiento de Dispositivos en la Red Local.
Utiliza SendARP nativo de Windows (Win32) y sockets multihilo para un escaneo rápido y preciso.
"""

import socket
import struct
import ctypes
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional
from core.oui_database import get_mac_vendor, is_randomized_mac


class NetworkScanner:
    """Escáner de red local para descubrir dispositivos conectados a la misma LAN."""

    def __init__(self):
        self._stop_requested = False
        try:
            self.SendARP = ctypes.windll.iphlpapi.SendARP
        except Exception:
            self.SendARP = None

    def stop_scan(self):
        """Detiene el escaneo activo."""
        self._stop_requested = True

    def _get_active_ip_and_gateway(self) -> (str, str):
        """Obtiene la IP local activa y el Gateway."""
        local_ip = "127.0.0.1"
        gateway_ip = "192.168.1.1"

        try:
            route_proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=3
            )
            for line in route_proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway_ip = parts[2]
                    local_ip = parts[3]
                    break
        except Exception:
            pass

        if local_ip == "127.0.0.1":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass

        return local_ip, gateway_ip

    def _resolve_hostname(self, ip: str) -> str:
        """Intenta resolver el nombre de host mediante DNS inverso con tiempo límite estricto."""
        try:
            socket.setdefaulttimeout(0.3)
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return "Desconocido"

    def _check_ports(self, ip: str, ports: List[int] = [80, 443, 22, 445, 8080]) -> List[int]:
        """Comprueba puertos comunes abiertos en el dispositivo."""
        open_ports = []
        for port in ports:
            if self._stop_requested:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        return open_ports

    def _arp_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Envía un paquete ARP a una IP mediante la API de Windows."""
        if not self.SendARP:
            return None

        try:
            dest_ip = struct.unpack('<I', socket.inet_aton(ip))[0]
            mac_buf = (ctypes.c_byte * 6)()
            mac_len = ctypes.c_ulong(6)
            res = self.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
            if res == 0:
                mac = ":".join(f"{b & 0xff:02X}" for b in mac_buf)
                return {
                    "ip": ip,
                    "mac": mac,
                    "online": True
                }
        except Exception:
            pass
        return None

    def get_system_arp_cache(self) -> Dict[str, str]:
        """Obtiene las entradas dinámicas de la tabla ARP actual del sistema Windows."""
        arp_cache = {}
        try:
            proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="ignore", timeout=3)
            for line in proc.stdout.splitlines():
                # Formato: 192.168.1.1   c8-33-74-e4-62-b4   dynamic
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})\s+([a-zA-Z]+)", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace("-", ":").upper()
                    mode = m.group(3).lower()
                    if mode in ("dynamic", "dinámico", "dinamico") and not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                        arp_cache[ip] = mac
        except Exception:
            pass
        return arp_cache

    def scan_network(
        self,
        subnet_base: Optional[str] = None,
        scan_ports: bool = True,
        progress_callback: Optional[Callable[[int, int, Optional[Dict[str, Any]]], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Escanea la subred local /24 (254 direcciones IP).
        Reporta el progreso mediante progress_callback(scanned_count, total_count, last_found_device).
        """
        self._stop_requested = False
        local_ip, gateway_ip = self._get_active_ip_and_gateway()

        # Determinar base de subred (ej: 192.168.1.)
        if not subnet_base:
            parts = local_ip.split(".")
            if len(parts) == 4 and parts[0] != "127":
                subnet_base = f"{parts[0]}.{parts[1]}.{parts[2]}."
            else:
                subnet_base = "192.168.1."

        # Cargar tabla ARP previa para descubrimiento instantáneo
        system_arp = self.get_system_arp_cache()

        ips_to_scan = [f"{subnet_base}{i}" for i in range(1, 255)]
        total_ips = len(ips_to_scan)
        scanned_count = 0
        devices: List[Dict[str, Any]] = []
        found_ips = set()

        # Obtener MAC de este equipo
        local_mac = "Desconocido"
        try:
            # Buscar en ipconfig o netsh
            proc = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True, errors="ignore", timeout=2)
            for line in proc.stdout.splitlines():
                m = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", line)
                if m:
                    local_mac = m.group(1).replace("-", ":").upper()
                    break
        except Exception:
            pass

        # Primero registrar de inmediato la IP del propio equipo
        this_device = {
            "ip": local_ip,
            "mac": local_mac,
            "vendor": get_mac_vendor(local_mac),
            "hostname": socket.gethostname(),
            "role": "Este Equipo (Tu PC)",
            "is_local": True,
            "is_gateway": False,
            "ports": [],
            "status": "Online"
        }
        devices.append(this_device)
        found_ips.add(local_ip)

        # Escanear con ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(self._arp_single_ip, ip): ip for ip in ips_to_scan}

            for future in as_completed(future_to_ip):
                if self._stop_requested:
                    break

                scanned_count += 1
                ip = future_to_ip[future]
                res = None

                try:
                    res = future.result()
                except Exception:
                    pass

                # Si SendARP falló pero la IP está en la caché ARP de Windows
                if not res and ip in system_arp:
                    res = {"ip": ip, "mac": system_arp[ip], "online": True}

                last_found = None
                if res and ip not in found_ips:
                    found_ips.add(ip)
                    mac = res["mac"]
                    vendor = get_mac_vendor(mac)
                    is_gw = (ip == gateway_ip)
                    role = "Router / Puerta de Enlace" if is_gw else "Dispositivo de Red"

                    hostname = self._resolve_hostname(ip)
                    ports = self._check_ports(ip) if scan_ports else []

                    device_entry = {
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "hostname": hostname,
                        "role": role,
                        "is_local": False,
                        "is_gateway": is_gw,
                        "ports": ports,
                        "status": "Online",
                        "is_private_mac": is_randomized_mac(mac)
                    }
                    devices.append(device_entry)
                    last_found = device_entry

                if progress_callback:
                    progress_callback(scanned_count, total_ips, last_found)

        # Ordenar lista por IP (primer octeto final como número)
        def ip_sort_key(dev):
            parts = dev["ip"].split(".")
            try:
                return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
            except Exception:
                return (999, 999, 999, 999)

        devices.sort(key=ip_sort_key)
        return devices
