"""
Módulo de Análisis de Red Wi-Fi y Conexión Activa.
Extrae detalles técnicos del punto de acceso (AP), cifrado, señal, gateway y DNS.
"""

import subprocess
import re
import socket
import struct
import ctypes
from typing import Dict, Any, List, Optional
from core.oui_database import get_mac_vendor


class WiFiAnalyzer:
    """Analizador de la interfaz y conexión Wi-Fi en Windows."""

    def __init__(self):
        pass

    def get_wifi_interface_info(self) -> Dict[str, Any]:
        """
        Ejecuta 'netsh wlan show interfaces' y parsea todos los campos clave de la conexión activa.
        """
        result = {
            "connected": False,
            "interface_name": "No detectada",
            "ssid": "Desconectado",
            "bssid": "N/A",
            "ap_vendor": "N/A",
            "signal_percent": 0,
            "rssi_dbm": "N/A",
            "band": "N/A",
            "channel": "N/A",
            "radio_type": "N/A",
            "authentication": "N/A",
            "cipher": "N/A",
            "receive_rate_mbps": "N/A",
            "transmit_rate_mbps": "N/A",
            "security_level": "Desconocido",
            "security_color": "gray",
            "security_notes": [],
            "raw_output": ""
        }

        try:
            proc = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=5
            )
            out = proc.stdout
            result["raw_output"] = out

            # Buscar bloque de interfaz conectada
            interfaces = re.split(r"\n(?=\s*Name\s*:|\s*Nombre\s*:)", out)
            active_block = None

            for block in interfaces:
                if re.search(r"State\s*:\s*connected|Estado\s*:\s*conectado", block, re.IGNORECASE):
                    active_block = block
                    break

            if not active_block:
                # Si no se encuentra un bloque explícito 'connected', revisar todo el output
                if "connected" in out.lower() or "conectado" in out.lower():
                    active_block = out

            if active_block:
                result["connected"] = True

                # Extraer nombre
                m = re.search(r"(?:Name|Nombre)\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["interface_name"] = m.group(1).strip()

                # SSID
                m = re.search(r"\bSSID\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["ssid"] = m.group(1).strip()

                # BSSID (MAC del Punto de Acceso)
                m = re.search(r"(?:BSSID|AP BSSID)\s*:\s*([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})", active_block)
                if m:
                    bssid = m.group(1).strip().replace("-", ":").upper()
                    result["bssid"] = bssid
                    result["ap_vendor"] = get_mac_vendor(bssid)

                # Señal %
                m = re.search(r"(?:Signal|Señal)\s*:\s*(\d+)%", active_block)
                if m:
                    result["signal_percent"] = int(m.group(1))

                # RSSI
                m = re.search(r"Rssi\s*:\s*(-?\d+)", active_block)
                if m:
                    result["rssi_dbm"] = f"{m.group(1)} dBm"

                # Banda (2.4 GHz / 5 GHz / 6 GHz)
                m = re.search(r"(?:Band|Banda)\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["band"] = m.group(1).strip()

                # Canal
                m = re.search(r"(?:Channel|Canal)\s*:\s*(\d+)", active_block)
                if m:
                    result["channel"] = m.group(1).strip()

                # Tipo de radio
                m = re.search(r"(?:Radio type|Tipo de radio)\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["radio_type"] = m.group(1).strip()

                # Autenticación
                m = re.search(r"(?:Authentication|Autenticación)\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["authentication"] = m.group(1).strip()

                # Cifrado
                m = re.search(r"(?:Cipher|Cifrado)\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["cipher"] = m.group(1).strip()

                # Velocidades
                m = re.search(r"(?:Receive rate|Velocidad de recepción)\s*(?:\(Mbps\))?\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["receive_rate_mbps"] = m.group(1).strip()

                m = re.search(r"(?:Transmit rate|Velocidad de transmisión)\s*(?:\(Mbps\))?\s*:\s*([^\r\n]+)", active_block)
                if m:
                    result["transmit_rate_mbps"] = m.group(1).strip()

                # Evaluar seguridad
                self._evaluate_wifi_security(result)

        except Exception as e:
            result["security_notes"].append(f"Error al consultar interfaz Wi-Fi: {str(e)}")

        return result

    def _evaluate_wifi_security(self, res: Dict[str, Any]):
        """Evalúa el nivel de seguridad del protocolo y cifrado Wi-Fi."""
        auth = res["authentication"].upper()
        cipher = res["cipher"].upper()
        notes = []

        if "OPEN" in auth or "ABIERTA" in auth or "NONE" in auth:
            res["security_level"] = "PELIGRO CRÍTICO (Red Abierta)"
            res["security_color"] = "#ff4444"
            notes.append("La red NO tiene contraseña ni cifrado. Todo tu tráfico web no-HTTPS puede ser interceptado por cualquiera en el área.")
        elif "WEP" in auth or "WEP" in cipher:
            res["security_level"] = "VULNERABLE (Cifrado WEP Roto)"
            res["security_color"] = "#ff4444"
            notes.append("El protocolo WEP fue vulnerado hace años. Un atacante puede descifrar la clave en menos de 5 minutos mediante inyección de paquetes.")
        elif "TKIP" in cipher:
            res["security_level"] = "PRECAUCIÓN (Cifrado TKIP Antiguo)"
            res["security_color"] = "#ffbb33"
            notes.append("Usa TKIP, un algoritmo vulnerable a ataques de descifrado parcial. Se recomienda cambiar a CCMP (AES).")
        elif "WPA3" in auth:
            res["security_level"] = "MÁXIMA SEGURIDAD (WPA3)"
            res["security_color"] = "#00C851"
            notes.append("Protocolo WPA3 activo con protección avanzada contra ataques de fuerza bruta y diccionario.")
        elif "WPA2" in auth:
            res["security_level"] = "SEGURO (WPA2 Estándar)"
            res["security_color"] = "#00C851"
            notes.append("Protocolo WPA2-Personal estándar con cifrado robusto CCMP (AES).")
        else:
            res["security_level"] = f"Información ({auth})"
            res["security_color"] = "#33b5e5"

        if res["signal_percent"] > 0 and res["signal_percent"] < 35:
            notes.append(f"Señal baja ({res['signal_percent']}%). En redes lejanas o débiles hay mayor riesgo de caídas y ataques de desautenticación (Deauth).")

        res["security_notes"] = notes

    def get_network_gateway_and_dns(self) -> Dict[str, Any]:
        """
        Obtiene la dirección IP y MAC de la Puerta de Enlace (Default Gateway),
        la IP local del equipo y los servidores DNS configurados.
        """
        data = {
            "gateway_ip": "Desconocido",
            "gateway_mac": "Desconocido",
            "gateway_vendor": "Desconocido",
            "local_ip": "Desconocido",
            "subnet_mask": "255.255.255.0",
            "dns_servers": [],
            "dns_providers": []
        }

        # 1. Obtener Gateway e IP local mediante 'route print 0.0.0.0'
        try:
            route_proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=4
            )
            for line in route_proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    data["gateway_ip"] = parts[2]
                    data["local_ip"] = parts[3]
                    break
        except Exception:
            pass

        # Fallback para IP local usando socket si falló route print
        if data["local_ip"] == "Desconocido":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                data["local_ip"] = s.getsockname()[0]
                s.close()
            except Exception:
                pass

        # 2. Obtener MAC del Gateway usando SendARP nativo de Windows (Win32 API)
        if data["gateway_ip"] != "Desconocido":
            try:
                SendARP = ctypes.windll.iphlpapi.SendARP
                dest_ip = struct.unpack('<I', socket.inet_aton(data["gateway_ip"]))[0]
                mac_buf = (ctypes.c_byte * 6)()
                mac_len = ctypes.c_ulong(6)
                res = SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
                if res == 0:
                    mac = ":".join(f"{b & 0xff:02X}" for b in mac_buf)
                    data["gateway_mac"] = mac
                    data["gateway_vendor"] = get_mac_vendor(mac)
            except Exception:
                pass

        # 3. Obtener Servidores DNS con PowerShell o ipconfig
        try:
            ps_proc = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"
                ],
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=4
            )
            dns_list = []
            for line in ps_proc.stdout.splitlines():
                line = line.strip()
                if line and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    if line not in dns_list:
                        dns_list.append(line)

            data["dns_servers"] = dns_list
        except Exception:
            pass

        # Si powershell no devolvió DNS, parsear ipconfig
        if not data["dns_servers"]:
            try:
                ip_proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors="ignore", timeout=4)
                dns_matches = re.findall(r"(?:DNS Servers|Servidores DNS)[ .]*:\s*([0-9.]+)", ip_proc.stdout)
                for dns in dns_matches:
                    if dns not in data["dns_servers"]:
                        data["dns_servers"].append(dns)
            except Exception:
                pass

        # Identificar proveedores de DNS
        for dns in data["dns_servers"]:
            prov = self._identify_dns_provider(dns, data["gateway_ip"])
            data["dns_providers"].append({"ip": dns, "provider": prov})

        return data

    def _identify_dns_provider(self, dns_ip: str, gateway_ip: str) -> str:
        """Identifica a qué servicio o entidad pertenece un servidor DNS."""
        if dns_ip == gateway_ip:
            return "Router Local (Gateway / Reenvío DNS del ISP)"
        if dns_ip in ("8.8.8.8", "8.8.4.4"):
            return "Google Public DNS (Oficial)"
        if dns_ip in ("1.1.1.1", "1.0.0.1"):
            return "Cloudflare DNS (Alta Privacidad)"
        if dns_ip in ("9.9.9.9", "149.112.112.112"):
            return "Quad9 DNS (Protección contra Malware)"
        if dns_ip in ("208.67.222.222", "208.67.220.220"):
            return "Cisco OpenDNS"
        if dns_ip.startswith("100.") or dns_ip.startswith("100.100."):
            return "VPN / Tailscale / Red Privada CGNAT"
        if dns_ip.startswith("192.168.") or dns_ip.startswith("10."):
            return "Servidor DNS Privado Local"
        return "Servidor DNS de Proveedor / ISP"

    def get_full_analysis(self) -> Dict[str, Any]:
        """Ejecuta y combina el análisis de Wi-Fi y configuración de red."""
        wifi_info = self.get_wifi_interface_info()
        net_info = self.get_network_gateway_and_dns()

        return {
            "wifi": wifi_info,
            "network": net_info
        }
