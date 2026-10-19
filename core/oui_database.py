"""
Base de datos y resolución de fabricantes de tarjetas de red (OUI - Organizationally Unique Identifier).
Permite identificar la marca o fabricante de cada dispositivo detectado en la red local.
"""

# Diccionario enriquecido de prefijos OUI (primeros 3 bytes / 6 caracteres hexadecimales)
OUI_DATABASE = {
    # Apple
    "00:17:F2": "Apple Inc.", "00:19:E3": "Apple Inc.", "00:1B:63": "Apple Inc.",
    "00:1E:52": "Apple Inc.", "00:23:12": "Apple Inc.", "00:25:00": "Apple Inc.",
    "00:26:08": "Apple Inc.", "28:CF:E9": "Apple Inc.", "38:CA:DA": "Apple Inc.",
    "3C:07:54": "Apple Inc.", "40:6C:8F": "Apple Inc.", "44:00:10": "Apple Inc.",
    "48:60:5F": "Apple Inc.", "68:96:7B": "Apple Inc.", "70:56:81": "Apple Inc.",
    "78:4F:43": "Apple Inc.", "88:66:5A": "Apple Inc.", "90:72:40": "Apple Inc.",
    "98:01:A7": "Apple Inc.", "98:E2:55": "Apple Inc.", "A4:83:E7": "Apple Inc.",
    "AC:DE:48": "Apple Inc.", "B8:78:26": "Apple Inc.", "BC:92:6B": "Apple Inc.",
    "C8:B5:B7": "Apple Inc.", "DC:2B:61": "Apple Inc.", "E0:B9:BA": "Apple Inc.",
    "F0:18:98": "Apple Inc.", "F4:F1:5A": "Apple Inc.", "F8:27:93": "Apple Inc.",

    # Samsung
    "00:07:AB": "Samsung Electronics", "00:12:47": "Samsung Electronics",
    "00:15:99": "Samsung Electronics", "00:16:6C": "Samsung Electronics",
    "00:21:D1": "Samsung Electronics", "00:24:91": "Samsung Electronics",
    "14:49:E0": "Samsung Electronics", "18:67:B0": "Samsung Electronics",
    "24:4B:03": "Samsung Electronics", "2C:4D:54": "Samsung Electronics",
    "34:BE:00": "Samsung Electronics", "40:0E:85": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics", "5C:A3:9D": "Samsung Electronics",
    "78:47:1D": "Samsung Electronics", "84:25:19": "Samsung Electronics",
    "94:35:0A": "Samsung Electronics", "AC:5F:3E": "Samsung Electronics",
    "BC:44:86": "Samsung Electronics", "CC:07:AB": "Samsung Electronics",
    "DC:71:44": "Samsung Electronics", "E8:50:8B": "Samsung Electronics",

    # Xiaomi / Redmi / POCO
    "00:EC:0A": "Xiaomi Communications", "18:59:36": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications", "34:80:0D": "Xiaomi Communications",
    "50:64:2B": "Xiaomi Communications", "64:09:80": "Xiaomi Communications",
    "7C:49:EB": "Xiaomi Communications", "84:F3:EB": "Xiaomi Communications",
    "98:FA:E3": "Xiaomi Communications", "AC:C1:EE": "Xiaomi Communications",
    "C4:0B:D3": "Xiaomi Communications", "D4:97:0B": "Xiaomi Communications",

    # Google / Alphabet (Pixel, Chromecast, Nest, Home)
    "00:1A:11": "Google, Inc.", "18:26:66": "Google, Inc.",
    "1C:53:F9": "Google, Inc.", "20:DF:B9": "Google, Inc.",
    "3C:5A:B4": "Google, Inc.", "44:07:0B": "Google, Inc.",
    "54:60:09": "Google, Inc.", "74:75:48": "Google, Inc.",
    "84:D6:D0": "Google, Inc.", "94:EB:CD": "Google, Inc.",
    "A4:77:33": "Google, Inc.", "D4:F5:47": "Google, Inc.",
    "F8:0F:F9": "Google, Inc.", "F8:8F:C2": "Google, Inc.",

    # Routers / Redes: ZTE, Digi, Huawei, TP-Link, ASUS, Cisco, Netgear, D-Link, AVM
    "C8:33:74": "ZTE Corporation (Router DIGI)", "CA:33:74": "ZTE Corporation (Router DIGI)",
    "00:1E:73": "ZTE Corporation", "00:22:93": "ZTE Corporation",
    "08:18:1A": "ZTE Corporation", "10:51:72": "ZTE Corporation",
    "34:E3:80": "ZTE Corporation", "70:85:40": "ZTE Corporation",
    "8C:E0:81": "ZTE Corporation", "94:A7:B7": "ZTE Corporation",
    "A0:EC:80": "ZTE Corporation", "DC:02:8E": "ZTE Corporation",

    # Huawei
    "00:18:82": "Huawei Technologies", "00:25:9E": "Huawei Technologies",
    "04:25:C5": "Huawei Technologies", "10:1B:54": "Huawei Technologies",
    "20:08:89": "Huawei Technologies", "38:4C:90": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies", "78:6A:89": "Huawei Technologies",
    "80:B6:86": "Huawei Technologies", "A4:99:9B": "Huawei Technologies",
    "E4:68:A3": "Huawei Technologies", "F4:C4:79": "Huawei Technologies",

    # TP-Link
    "00:27:19": "TP-Link Corporation", "14:CC:20": "TP-Link Corporation",
    "18:D6:C7": "TP-Link Corporation", "30:B5:C2": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation", "60:32:B1": "TP-Link Corporation",
    "70:4F:57": "TP-Link Corporation", "84:16:F9": "TP-Link Corporation",
    "90:F6:52": "TP-Link Corporation", "A8:57:4E": "TP-Link Corporation",
    "C0:25:E9": "TP-Link Corporation", "E8:48:B8": "TP-Link Corporation",

    # Asus / AVM Fritz!Box / Netgear / Cisco
    "00:11:D8": "ASUSTek Computer", "04:D9:F5": "ASUSTek Computer",
    "10:7B:44": "ASUSTek Computer", "1C:87:2C": "ASUSTek Computer",
    "2C:FD:A1": "ASUSTek Computer", "38:D5:47": "ASUSTek Computer",
    "00:04:0E": "AVM GmbH (FRITZ!Box)", "00:1C:4A": "AVM GmbH (FRITZ!Box)",
    "2C:39:96": "AVM GmbH (FRITZ!Box)", "34:81:C4": "AVM GmbH (FRITZ!Box)",
    "00:09:5B": "Netgear Inc.", "00:14:6C": "Netgear Inc.", "20:E5:2A": "Netgear Inc.",
    "00:00:0C": "Cisco Systems", "00:01:42": "Cisco Systems", "00:12:7F": "Cisco Systems",

    # Chipsets de red (PC / Laptops): Intel, Realtek, Qualcomm, Broadcom, Killer
    "BC:F4:D4": "Qualcomm Technologies (Adaptador Wi-Fi)",
    "BE:F4:D4": "Qualcomm Technologies",
    "00:03:7F": "Qualcomm Atheros", "00:13:74": "Qualcomm Atheros",
    "00:03:47": "Intel Corporation", "00:04:23": "Intel Corporation",
    "00:0E:35": "Intel Corporation", "00:13:02": "Intel Corporation",
    "00:15:00": "Intel Corporation", "00:1B:21": "Intel Corporation",
    "00:21:6A": "Intel Corporation", "34:13:E8": "Intel Corporation",
    "48:51:B7": "Intel Corporation", "70:1C:E8": "Intel Corporation",
    "8C:85:90": "Intel Corporation", "A4:4C:C8": "Intel Corporation",
    "DC:53:60": "Intel Corporation", "F8:63:3F": "Intel Corporation",
    "00:07:0E": "Realtek Semiconductor", "00:10:60": "Realtek Semiconductor",
    "00:E0:4C": "Realtek Semiconductor", "4C:D7:17": "Realtek Semiconductor",
    "52:54:00": "QEMU / KVM Virtual NIC", "00:15:5D": "Microsoft Hyper-V NIC",
    "00:50:56": "VMware Virtual NIC", "08:00:27": "Oracle VirtualBox NIC",

    # IoT, Domótica y Gadgets (Espressif, Raspberry Pi, Amazon, Sonos, Philips, Sony, Nintendo)
    "24:0A:C4": "Espressif Systems (ESP8266/ESP32 IoT)",
    "24:62:AB": "Espressif Systems (ESP32 IoT)",
    "30:AE:A4": "Espressif Systems (ESP32 IoT)",
    "84:0D:8E": "Espressif Systems (ESP32 IoT)",
    "84:CC:A8": "Espressif Systems (ESP32 IoT)",
    "A4:CF:12": "Espressif Systems (ESP8266 IoT)",
    "B4:E6:2D": "Espressif Systems (ESP32 IoT)",
    "DC:4F:22": "Espressif Systems (ESP32 IoT)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:18:78": "Amazon Technologies (Echo / FireTV / Kindle)",
    "44:65:0D": "Amazon Technologies (Echo / Alexa)",
    "68:37:E9": "Amazon Technologies (Echo / Alexa)",
    "74:C2:46": "Amazon Technologies (Echo / Alexa)",
    "00:0E:58": "Sonos Inc.", "5C:AA:FD": "Sonos Inc.", "94:9F:3E": "Sonos Inc.",
    "00:17:88": "Philips Lighting (Hue)", "EC:B5:FA": "Philips Lighting",
    "00:04:1F": "Sony Interactive Entertainment (PlayStation)",
    "00:1D:0D": "Sony Interactive Entertainment (PlayStation)",
    "F8:46:1C": "Sony Interactive Entertainment (PlayStation)",
    "00:09:BF": "Nintendo Co., Ltd. (Switch / Wii)",
    "98:B6:E9": "Nintendo Co., Ltd. (Switch)",
    "00:17:FA": "Microsoft Corp. (Xbox)", "7C:ED:8D": "Microsoft Corp. (Xbox)"
}

_mac_cache = {}


def is_randomized_mac(mac: str) -> bool:
    """
    Detecta si una dirección MAC es privada / aleatorizada (Locally Administered Address).
    Los teléfonos modernos (iOS 14+, Android 10+, Windows 10/11) usan MACs aleatorias
    para proteger la privacidad en redes Wi-Fi.
    El segundo dígito hexadecimal tiene el bit U/L (Universal/Local) en 1: 2, 6, A, E.
    """
    if not mac or len(mac) < 2:
        return False
    clean = mac.replace(":", "").replace("-", "")
    if len(clean) < 2:
        return False
    try:
        second_nibble = clean[1].upper()
        return second_nibble in ("2", "6", "A", "E")
    except Exception:
        return False


def get_mac_vendor(mac: str, check_online: bool = False) -> str:
    """
    Obtiene el nombre del fabricante a partir de la dirección MAC.
    Normaliza el formato a XX:XX:XX y busca en la base de datos local.
    """
    if not mac:
        return "Desconocido"

    clean_mac = mac.strip().upper().replace("-", ":")
    parts = clean_mac.split(":")
    if len(parts) < 3:
        return "Dirección MAC inválida"

    # Verificar si es broadcast o multicast
    if clean_mac == "FF:FF:FF:FF:FF:FF":
        return "Difusión (Broadcast)"
    if clean_mac.startswith("01:00:5E") or clean_mac.startswith("33:33:"):
        return "Multidifusión (Multicast)"

    prefix = ":".join(parts[:3])

    if prefix in _mac_cache:
        return _mac_cache[prefix]

    # Búsqueda en base de datos local
    if prefix in OUI_DATABASE:
        vendor = OUI_DATABASE[prefix]
        _mac_cache[prefix] = vendor
        return vendor

    # Verificar si es una MAC privada / aleatoria de dispositivo móvil
    if is_randomized_mac(clean_mac):
        vendor = "Dispositivo móvil (MAC Privada/Aleatoria - iOS/Android)"
        _mac_cache[prefix] = vendor
        return vendor

    # Consulta opcional en línea ligera
    if check_online:
        try:
            import urllib.request
            import json
            url = f"https://api.maclookup.app/v2/macs/{clean_mac}"
            req = urllib.request.Request(url, headers={"User-Agent": "WiFi-Inspector/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("success") and data.get("company"):
                    comp = data["company"]
                    _mac_cache[prefix] = comp
                    return comp
        except Exception:
            pass

    vendor = "Fabricante no catalogado"
    _mac_cache[prefix] = vendor
    return vendor
