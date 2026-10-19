"""
Módulo de Auditoría de Ciberseguridad y Detección de Amenazas.
Analiza riesgos de espionaje, intercepción (Man-In-The-Middle), envenenamiento ARP,
secuestro de DNS, puertos en escucha no autorizados y conexiones sospechosas.
"""

import socket
import subprocess
import re
from typing import Dict, Any, List, Optional
import psutil
from core.wifi_analyzer import WiFiAnalyzer


class SecurityAuditor:
    """Auditor de seguridad para detectar si el usuario está siendo espiado o intervenido."""

    def __init__(self):
        self.wifi_analyzer = WiFiAnalyzer()

    def check_arp_spoofing(self, network_devices: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Detecta indicios de ARP Poisoning / Spoofing (Ataque Man-In-The-Middle).
        En un ataque MitM, el atacante envía respuestas ARP fraudulentas para asociar
        la IP de la Puerta de Enlace (Router) con su propia dirección MAC.
        """
        result = {
            "detected": False,
            "severity": "NORMAL",
            "title": "Inspección de Envenenamiento ARP (MitM)",
            "details": [],
            "duplicate_macs": {}
        }

        # Obtener tabla ARP del sistema
        arp_table = {}
        try:
            proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, errors="ignore", timeout=3)
            for line in proc.stdout.splitlines():
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})\s+([a-zA-Z]+)", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace("-", ":").upper()
                    mode = m.group(3).lower()
                    if mode in ("dynamic", "dinámico", "dinamico") and not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                        arp_table[ip] = mac
        except Exception as e:
            result["details"].append(f"No se pudo leer la tabla ARP: {e}")

        # Si tenemos dispositivos del escaneo reciente, complementar
        if network_devices:
            for dev in network_devices:
                ip = dev.get("ip")
                mac = dev.get("mac")
                if ip and mac and mac != "Desconocido":
                    arp_table[ip] = mac

        # Detectar MACs duplicadas en diferentes IPs
        mac_to_ips = {}
        for ip, mac in arp_table.items():
            if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                continue
            mac_to_ips.setdefault(mac, []).append(ip)

        duplicates = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
        result["duplicate_macs"] = duplicates

        # Obtener IP del gateway
        net_info = self.wifi_analyzer.get_network_gateway_and_dns()
        gw_ip = net_info.get("gateway_ip")
        gw_mac = net_info.get("gateway_mac")

        if duplicates:
            # Comprobar si el Gateway está involucrado en una MAC duplicada
            is_gateway_affected = False
            for mac, ips in duplicates.items():
                if gw_ip in ips:
                    is_gateway_affected = True
                    result["detected"] = True
                    result["severity"] = "CRÍTICO"
                    result["details"].append(
                        f"¡ALERTA CRÍTICA DE INTERVENCIÓN! La dirección MAC del Router ({mac}) "
                        f"está asignada a múltiples IPs: {', '.join(ips)}. Esto es un indicio clásico de "
                        "ataque ARP Spoofing (Man-in-the-Middle). Alguien en tu red podría estar interceptando tus datos."
                    )

            if not is_gateway_affected:
                result["detected"] = True
                result["severity"] = "ADVERTENCIA"
                for mac, ips in duplicates.items():
                    result["details"].append(
                        f"Dirección MAC duplicada ({mac}) compartida por: {', '.join(ips)}. "
                        "Podría tratarse de un extensor Wi-Fi o de un intento de suplantación de identidad."
                    )
        else:
            result["details"].append(
                "Tabla ARP limpia. Cada dirección IP tiene una dirección física MAC única. "
                "No hay indicios de envenenamiento ARP ni desvío de tráfico en este momento."
            )

        return result

    def check_dns_hijacking(self) -> Dict[str, Any]:
        """
        Verifica si los servidores DNS configurados están alterados o si las resoluciones
        están siendo manipuladas (DNS Poisoning / Redirección fraudulenta).
        """
        result = {
            "detected": False,
            "severity": "NORMAL",
            "title": "Integridad de Servidores y Respuestas DNS",
            "details": [],
            "dns_servers": []
        }

        net_info = self.wifi_analyzer.get_network_gateway_and_dns()
        dns_servers = net_info.get("dns_servers", [])
        result["dns_servers"] = dns_servers

        if not dns_servers:
            result["details"].append("No se pudieron detectar servidores DNS locales.")
            return result

        # Probar resolución de dominio canario (google.com)
        test_domain = "google.com"
        local_ips = []
        try:
            addr_info = socket.getaddrinfo(test_domain, 80, socket.AF_INET)
            local_ips = list(set([item[4][0] for item in addr_info]))
        except Exception as e:
            result["details"].append(f"Error al resolver {test_domain}: {e}")

        # Comprobar si resuelve a IPs privadas (lo que sería un secuestro descarado)
        for ip in local_ips:
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
                result["detected"] = True
                result["severity"] = "CRÍTICO"
                result["details"].append(
                    f"¡PELIGRO! El dominio {test_domain} resolvió a una IP privada ({ip}). "
                    "Tus peticiones DNS están siendo secuestradas hacia un servidor local no oficial."
                )

        if not result["detected"]:
            result["details"].append(
                f"Servidores DNS activos: {', '.join(dns_servers)}. "
                f"Las respuestas para dominios públicos resuelven correctamente sin redirecciones fraudulentas."
            )

        return result

    def check_listening_ports(self) -> Dict[str, Any]:
        """
        Inspecciona puertos que el equipo tiene abiertos y a la escucha (LISTEN).
        Diferencia entre puertos que solo escuchan en Localhost (127.0.0.1) y los que
        están expuestos a toda la red Wi-Fi (0.0.0.0 o ::).
        """
        result = {
            "detected": False,
            "severity": "NORMAL",
            "title": "Auditoría de Puertos en Escucha Local (Listeners)",
            "exposed_services": [],
            "localhost_services": [],
            "suspicious_processes": []
        }

        # Puertos conocidos sospechosos comunes de troyanos / backdoors
        known_suspicious_ports = {
            1337: "Backdoor / RAT",
            31337: "Back Orifice / Trojan",
            4444: "Metasploit Default Listener",
            5555: "Android ADB no autorizado",
            6666: "IRC Botnet",
            6667: "IRC Botnet",
            9999: "Backdoor Listener"
        }

        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'LISTEN':
                    laddr = conn.laddr
                    port = laddr.port
                    ip = laddr.ip
                    pid = conn.pid

                    proc_name = "Desconocido"
                    proc_path = ""
                    if pid:
                        try:
                            p = psutil.Process(pid)
                            proc_name = p.name()
                            proc_path = p.exe()
                        except Exception:
                            pass

                    item = {
                        "port": port,
                        "ip": ip,
                        "pid": pid,
                        "process": proc_name,
                        "path": proc_path,
                        "is_global": (ip in ("0.0.0.0", "::"))
                    }

                    if port in known_suspicious_ports:
                        result["detected"] = True
                        result["severity"] = "CRÍTICO"
                        result["suspicious_processes"].append(
                            f"¡Puerto sospechoso detectado! Puerto {port} ({known_suspicious_ports[port]}) "
                            f"abierto por el proceso '{proc_name}' (PID: {pid})."
                        )

                    if item["is_global"]:
                        result["exposed_services"].append(item)
                    else:
                        result["localhost_services"].append(item)

        except Exception as e:
            result["suspicious_processes"].append(f"Error al auditar puertos: {e}")

        if result["exposed_services"] and result["severity"] == "NORMAL":
            result["severity"] = "INFORMATIVO"

        return result

    def check_wifi_security(self) -> Dict[str, Any]:
        """Verifica riesgos en la conexión Wi-Fi (cifrado y señal)."""
        wifi_data = self.wifi_analyzer.get_wifi_interface_info()

        result = {
            "detected": False,
            "severity": "NORMAL",
            "title": "Seguridad de la Red Wi-Fi",
            "details": []
        }

        if not wifi_data["connected"]:
            result["details"].append("No hay interfaz Wi-Fi conectada actualmente.")
            return result

        auth = wifi_data["authentication"].upper()
        cipher = wifi_data["cipher"].upper()

        if "OPEN" in auth or "ABIERTA" in auth or "NONE" in auth:
            result["detected"] = True
            result["severity"] = "CRÍTICO"
            result["details"].append(
                "¡CONEXIÓN EN PELIGRO! Estás conectado a una red Wi-Fi ABIERTA sin contraseña. "
                "Cualquier atacante conectado a la misma red puede interceptar tu navegación, credenciales no cifradas y cookies."
            )
        elif "WEP" in auth or "WEP" in cipher:
            result["detected"] = True
            result["severity"] = "CRÍTICO"
            result["details"].append(
                "¡Cifrado WEP obsoleto! Este cifrado puede ser vulnerado en minutos con herramientas estándar."
            )
        elif "TKIP" in cipher:
            result["detected"] = True
            result["severity"] = "ADVERTENCIA"
            result["details"].append(
                "Cifrado TKIP detectado. Aunque requiere contraseña, es vulnerable a ataques criptográficos. Usa AES/CCMP."
            )
        else:
            result["details"].append(
                f"Red protegida correctamente mediante {wifi_data['authentication']} y cifrado {wifi_data['cipher']}."
            )

        return result

    def run_full_security_audit(self, network_devices: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Ejecuta todas las comprobaciones de seguridad y calcula un Score Global de Ciberseguridad.
        Puntuación de 0 a 100 (100 = Máxima seguridad, sin amenazas).
        """
        arp_check = self.check_arp_spoofing(network_devices)
        dns_check = self.check_dns_hijacking()
        ports_check = self.check_listening_ports()
        wifi_check = self.check_wifi_security()

        score = 100
        threats_count = 0
        warnings_count = 0
        recommendations = []

        # Evaluar impacto de ARP Spoofing
        if arp_check["severity"] == "CRÍTICO":
            score -= 50
            threats_count += 1
            recommendations.append("Desconéctate de esta red de inmediato: Hay indicios graves de envenenamiento ARP (MitM).")
        elif arp_check["severity"] == "ADVERTENCIA":
            score -= 15
            warnings_count += 1
            recommendations.append("Verifica si tienes extensores o repetidores Wi-Fi que puedan estar duplicando MACs.")

        # Evaluar impacto de DNS
        if dns_check["severity"] == "CRÍTICO":
            score -= 40
            threats_count += 1
            recommendations.append("Restablece tus servidores DNS a servidores oficiales seguros (Cloudflare 1.1.1.1 o Google 8.8.8.8).")

        # Evaluar impacto de Wi-Fi
        if wifi_check["severity"] == "CRÍTICO":
            score -= 45
            threats_count += 1
            recommendations.append("No utilices redes Wi-Fi abiertas para transacciones bancarias o cuentas privadas sin una VPN cifrada.")
        elif wifi_check["severity"] == "ADVERTENCIA":
            score -= 10
            warnings_count += 1
            recommendations.append("Cambia en la configuración de tu router el cifrado de TKIP a WPA2-PSK (AES).")

        # Evaluar procesos sospechosos en puertos
        if ports_check["suspicious_processes"]:
            score -= 35
            threats_count += len(ports_check["suspicious_processes"])
            recommendations.append("Finaliza los procesos desconocidos que están a la escucha en puertos no estándar.")

        score = max(0, min(100, score))

        if score >= 85:
            overall_status = "SEGURO"
            status_color = "#00C851"
            status_description = "Tu conexión y equipo se encuentran protegidos. No se han detectado indicios de espionaje ni intercepción activa."
        elif score >= 60:
            overall_status = "PRECAUCIÓN"
            status_color = "#ffbb33"
            status_description = "Se han identificado observaciones o servicios que requieren tu atención para optimizar la seguridad."
        else:
            overall_status = "RIESGO ALTO"
            status_color = "#ff4444"
            status_description = "¡Peligro de vulnerabilidad o intervención detectado! Revisa los detalles de alerta a continuación."

        return {
            "score": score,
            "overall_status": overall_status,
            "status_color": status_color,
            "status_description": status_description,
            "threats_count": threats_count,
            "warnings_count": warnings_count,
            "arp_check": arp_check,
            "dns_check": dns_check,
            "ports_check": ports_check,
            "wifi_check": wifi_check,
            "recommendations": recommendations
        }
