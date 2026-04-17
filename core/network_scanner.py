# core/network_scanner.py — VERSION OPTIMISÉE
"""
Scanner réseau WiFi pour ARIA.
Cartographie automatique du réseau local.
"""

import socket
import subprocess
import platform
import concurrent.futures
import re
import json
import os
from datetime import datetime


class NetworkScanner:

    def __init__(self):
        self.os_type   = platform.system()
        self._arp_cache = {}   # ← Cache ARP (1 seul appel pour tout le réseau)

    # ─── SCAN PRINCIPAL ───────────────────────────────────────────
    def full_scan(self) -> dict:
        result = {
            "timestamp":    datetime.now().isoformat(),
            "network_info": self._get_network_info(),   # ← FIX : appels en parallèle
            "devices":      [],
            "open_ports":   {},
            "security":     {},
            "topology":     {}
        }

        gateway   = result["network_info"].get("gateway", "")
        local_ip  = result["network_info"].get("local_ip", "")
        net_range = self._get_network_range(local_ip)

        if net_range:
            print(f"🔍 Scan du réseau {net_range}...")
            devices = self._discover_devices(net_range)
            result["devices"] = devices

            # ← FIX : port scan en PARALLÈLE sur tous les appareils (pas séquentiel)
            result["open_ports"] = self._scan_all_ports(devices[:15])

        result["security"] = self._analyze_security(result)
        result["topology"] = self._build_topology(result)
        result["summary"]  = self._build_summary(result)

        self._save_scan(result)
        return result

    # ─── INFOS RÉSEAU LOCAL — en parallèle ───────────────────────
    def _get_network_info(self) -> dict:
        # ← FIX : les 4 appels système lancés en même temps
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_ip   = ex.submit(self._get_local_ip)
            f_gw   = ex.submit(self._get_gateway)
            f_ssid = ex.submit(self._get_wifi_ssid)
            f_dns  = ex.submit(self._get_dns_servers)
            local_ip = f_ip.result(timeout=5)
            gateway  = f_gw.result(timeout=5)
            ssid     = f_ssid.result(timeout=5)
            dns      = f_dns.result(timeout=5)

        return {
            "local_ip":    local_ip,
            "hostname":    socket.gethostname(),
            "gateway":     gateway,
            "ssid":        ssid,
            "os":          self.os_type,
            "dns_servers": dns
        }

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_gateway(self) -> str:
        try:
            if self.os_type == "Windows":
                out   = subprocess.check_output("ipconfig", shell=True, timeout=5).decode("cp850", errors="ignore")
                match = re.search(r"Passerelle.*?:\s*([\d.]+)", out)
                return match.group(1) if match else ""
            else:
                out   = subprocess.check_output("ip route", shell=True, timeout=5).decode()
                match = re.search(r"default via ([\d.]+)", out)
                return match.group(1) if match else ""
        except:
            return ""

    def _get_wifi_ssid(self) -> str:
        try:
            if self.os_type == "Windows":
                out   = subprocess.check_output(
                    "netsh wlan show interfaces", shell=True, timeout=5
                ).decode("cp850", errors="ignore")
                match = re.search(r"SSID\s+:\s+(.+)", out)
                return match.group(1).strip() if match else "Non connecté au WiFi"
            elif self.os_type == "Linux":
                out = subprocess.check_output("iwgetid -r", shell=True, timeout=5).decode().strip()
                return out or "Non détecté"
            elif self.os_type == "Darwin":
                out   = subprocess.check_output(
                    "/System/Library/PrivateFrameworks/Apple80211.framework"
                    "/Versions/Current/Resources/airport -I", shell=True, timeout=5
                ).decode()
                match = re.search(r"\s+SSID:\s+(.+)", out)
                return match.group(1).strip() if match else ""
        except:
            return "Non détecté"

    def _get_dns_servers(self) -> list:
        dns = []
        try:
            if self.os_type == "Windows":
                out     = subprocess.check_output(
                    "ipconfig /all", shell=True, timeout=5
                ).decode("cp850", errors="ignore")
                matches = re.findall(r"Serveurs DNS.*?:\s*([\d.]+)", out)
                dns     = matches[:3]
            else:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            dns.append(line.split()[1])
        except:
            pass
        return dns

    # ─── DÉCOUVERTE D'APPAREILS ───────────────────────────────────
    def _get_network_range(self, local_ip: str) -> str | None:
        if not local_ip or local_ip == "127.0.0.1":
            return None
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}"

    def _discover_devices(self, net_range: str) -> list:
        # ── Phase 1 : Ping sweep ──────────────────────────────────
        def ping(ip: str) -> bool:
            try:
                cmd    = f"ping -n 1 -w 300 {ip}" if self.os_type == "Windows" \
                         else f"ping -c 1 -W 1 {ip}"   # ← FIX : -w 300ms au lieu de 500ms
                result = subprocess.run(
                    cmd, shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return result.returncode == 0
            except:
                return False

        ips = [f"{net_range}.{i}" for i in range(1, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:  # ← FIX : 100 workers
            results = list(ex.map(ping, ips))

        alive_ips = [ip for ip, alive in zip(ips, results) if alive]
        print(f"✅ {len(alive_ips)} appareils détectés")

        # ── Phase 2 : Build ARP cache en 1 seul appel ────────────
        # ← FIX MAJEUR : 1 appel arp au lieu de N appels
        self._build_arp_cache()

        # ── Phase 3 : Enrichissement en PARALLÈLE ────────────────
        # ← FIX MAJEUR : hostname + mac + vendor tous en même temps
        def enrich(ip: str) -> dict:
            device = {
                "ip":       ip,
                "hostname": self._resolve_hostname_fast(ip),
                "mac":      self._arp_cache.get(ip, "?"),
                "vendor":   "",
                "type":     "unknown",
                "ports":    []
            }
            device["vendor"] = self._get_vendor(device["mac"])
            device["type"]   = self._guess_device_type(device)
            return device

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            devices = list(ex.map(enrich, alive_ips))

        return devices

    # ─── ARP CACHE — 1 seul appel pour tout le réseau ────────────
    def _build_arp_cache(self):
        """Lit la table ARP une seule fois et la met en cache."""
        try:
            if self.os_type == "Windows":
                out = subprocess.check_output("arp -a", shell=True, timeout=5).decode("cp850", errors="ignore")
            else:
                out = subprocess.check_output("arp -n", shell=True, timeout=5).decode()

            for line in out.splitlines():
                ip_match  = re.search(r"(\d{1,3}\.){3}\d{1,3}", line)
                mac_match = re.search(r"([\da-f]{2}[-:]){5}[\da-f]{2}", line, re.IGNORECASE)
                if ip_match and mac_match:
                    self._arp_cache[ip_match.group(0)] = mac_match.group(0).upper()
        except:
            pass

    # ─── HOSTNAME — avec timeout strict ──────────────────────────
    def _resolve_hostname_fast(self, ip: str) -> str:
        """Résolution avec timeout de 1s max — évite les blocages."""
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(socket.gethostbyaddr, ip)
                return future.result(timeout=1.0)[0]
        except:
            return ip

    def _get_vendor(self, mac: str) -> str:
        OUI = {
            "00:50:56": "VMware",       "00:0C:29": "VMware",
            "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
            "00:1A:11": "Google",       "F4:F5:D8": "Google",
            "B4:E6:2A": "Apple",        "3C:22:FB": "Apple",
            "00:25:90": "Samsung",      "FC:F8:AE": "Samsung",
            "E4:5F:01": "Xiaomi",       "00:E0:4C": "Realtek",
            "00:1B:21": "Intel",        "8C:8D:28": "Intel",
        }
        prefix = mac[:8].upper() if len(mac) >= 8 else ""
        return OUI.get(prefix, "Inconnu")

    def _guess_device_type(self, device: dict) -> str:
        hostname = device.get("hostname", "").lower()
        vendor   = device.get("vendor",   "").lower()
        if any(w in hostname for w in ["router", "gateway", "livebox", "bbox", "freebox"]):
            return "🌐 Routeur/Box"
        if any(w in hostname for w in ["phone", "iphone", "android", "mobile"]):
            return "📱 Smartphone"
        if any(w in hostname for w in ["printer", "print", "hp", "canon", "epson"]):
            return "🖨️ Imprimante"
        if "raspberry" in vendor or "raspberry" in hostname:
            return "🍓 Raspberry Pi"
        if "apple" in vendor:
            return "💻 Apple"
        if any(w in hostname for w in ["server", "srv", "nas"]):
            return "🖥️ Serveur/NAS"
        if any(w in hostname for w in ["cam", "camera", "ipcam", "cctv"]):
            return "📷 Caméra IP"
        return "💻 Appareil"

    # ─── SCAN DE PORTS — parallèle sur tous les appareils ────────
    def _scan_all_ports(self, devices: list) -> dict:
        """Lance le scan de ports sur tous les appareils EN MÊME TEMPS."""
        def scan_one(device):
            return device["ip"], self._scan_ports(device["ip"])

        open_ports = {}
        # ← FIX MAJEUR : 10 appareils en parallèle au lieu de séquentiel
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for ip, ports in ex.map(scan_one, devices):
                open_ports[ip] = ports
                if ports:
                    print(f"  📡 {ip} : {len(ports)} port(s) ouvert(s)")

        return open_ports

    def _scan_ports(self, ip: str) -> list:
        PORTS = {
            21: "FTP",      22: "SSH",    23: "Telnet",  25: "SMTP",
            53: "DNS",      80: "HTTP",  110: "POP3",   143: "IMAP",
           443: "HTTPS",   445: "SMB",  3306: "MySQL", 3389: "RDP",
          5900: "VNC",    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        RISKY = {23, 21, 3389, 5900, 445, 27017}

        def check(port):
            try:
                s  = socket.socket()
                s.settimeout(0.3)   # ← FIX : 0.3s au lieu de 0.5s
                ok = s.connect_ex((ip, port)) == 0
                s.close()
                return port, ok
            except:
                return port, False

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for port, is_open in ex.map(check, PORTS.keys()):
                if is_open:
                    open_ports.append({
                        "port":    port,
                        "service": PORTS[port],
                        "risk":    "🔴 RISQUE" if port in RISKY else "🟡 OK"
                    })
        return open_ports

    # ─── ANALYSE SÉCURITÉ ─────────────────────────────────────────
    # (inchangée — la logique est correcte)
    def _analyze_security(self, scan_result: dict) -> dict:
        issues    = []
        score     = 100
        devices   = scan_result.get("devices", [])
        all_ports = scan_result.get("open_ports", {})
        net_info  = scan_result.get("network_info", {})

        PORT_ISSUES = {
            23:    ("Critique", "Protocole",       "Telnet ouvert — protocole non chiffré",
                    "Désactiver Telnet, utiliser SSH (port 22)",
                    "Credentials en clair sur le réseau", 20),
            21:    ("Élevé",    "Protocole",       "FTP ouvert — transfert de fichiers non chiffré",
                    "Remplacer par SFTP ou FTPS",
                    "Données transférées lisibles en clair", 15),
            3389:  ("Élevé",    "Accès distant",   "RDP exposé sur tout le réseau local",
                    "Restreindre RDP via VPN uniquement, activer NLA",
                    "Cible privilégiée pour brute-force et ransomware", 15),
            5900:  ("Élevé",    "Accès distant",   "VNC exposé — bureau à distance non sécurisé",
                    "Tunneliser VNC via SSH, désactiver si inutilisé",
                    "Accès complet au bureau sans authentification forte", 15),
            445:   ("Élevé",    "Partage fichiers","SMB exposé — protocole cible de WannaCry/NotPetya",
                    "Bloquer SMB sur le firewall, appliquer les patches MS",
                    "Vecteur principal de propagation ransomware", 15),
            27017: ("Critique", "Base de données", "MongoDB exposé sans authentification probable",
                    "Activer l'auth MongoDB, bloquer l'accès externe",
                    "Accès complet à la base de données", 25),
        }

        for ip, ports in all_ports.items():
            for p in ports:
                if p["port"] in PORT_ISSUES:
                    sev, cat, issue, fix, impact, penalty = PORT_ISSUES[p["port"]]
                    issues.append({"severity": sev, "ip": ip, "category": cat,
                                   "issue": issue, "fix": fix, "impact": impact})
                    score -= penalty

        iot_devices  = [d for d in devices if any(
            w in d["type"].lower() for w in ["caméra", "imprimante", "raspberry", "iot"])]
        work_devices = [d for d in devices if any(
            w in d["type"].lower() for w in ["pc", "laptop", "serveur", "apple", "intel"])]

        if iot_devices and work_devices:
            issues.append({
                "severity": "Élevé", "ip": "Réseau", "category": "Segmentation",
                "issue":  f"{len(iot_devices)} appareil(s) IoT sur le même réseau que les postes de travail",
                "fix":    "Créer un VLAN dédié IoT (192.168.2.0/24) séparé du réseau principal",
                "impact": "Un appareil IoT compromis peut attaquer tous les postes de travail"
            })
            score -= 15

        if len(devices) > 15:
            issues.append({
                "severity": "Moyen", "ip": "Réseau", "category": "Segmentation",
                "issue":  f"Réseau plat avec {len(devices)} appareils — aucune microsegmentation",
                "fix":    "Mettre en place des VLANs : Bureau / IoT / Invités / Serveurs",
                "impact": "Un appareil compromis peut scanner et attaquer tous les autres"
            })
            score -= 10

        unknowns = [d for d in devices if d["vendor"] == "Inconnu"]
        if len(unknowns) >= 3:
            issues.append({
                "severity": "Moyen", "ip": "Réseau", "category": "Inventaire",
                "issue":  f"{len(unknowns)} appareils non identifiés sur le réseau",
                "fix":    "Établir un inventaire des appareils autorisés, activer le filtrage MAC",
                "impact": "Appareil non autorisé potentiellement connecté (rogue device)"
            })
            score -= 10

        dns_servers = net_info.get("dns_servers", [])
        public_dns  = [d for d in dns_servers if d in ["8.8.8.8","8.8.4.4","1.1.1.1","9.9.9.9"]]
        if public_dns:
            issues.append({
                "severity": "Faible", "ip": "DNS", "category": "DNS",
                "issue":  "DNS public utilisé — pas de filtrage DNS interne",
                "fix":    "Déployer Pi-hole ou AdGuard Home pour DNS filtering + DoH",
                "impact": "Pas de protection contre les domaines malveillants"
            })
            score -= 5

        gateway = net_info.get("gateway", "")
        if len(devices) > 3:
            issues.append({
                "severity": "Moyen", "ip": gateway or "Routeur", "category": "WiFi",
                "issue":  "WPS potentiellement activé (activé par défaut sur la plupart des box)",
                "fix":    "Désactiver WPS dans l'interface d'administration du routeur",
                "impact": "Brute-force du PIN WPS en < 11 000 tentatives (Pixie Dust attack)"
            })
            score -= 10

        gw_ports    = all_ports.get(gateway, [])
        admin_ports = [p for p in gw_ports if p["port"] in [80, 443, 8080, 8443]]
        if admin_ports:
            issues.append({
                "severity": "Moyen", "ip": gateway, "category": "Administration",
                "issue":  "Interface d'administration du routeur accessible sur le réseau",
                "fix":    "Changer le mot de passe admin par défaut, désactiver l'accès WAN",
                "impact": "Accès à la configuration complète du réseau"
            })
            score -= 8

        recommendations = self._generate_recommendations(issues, devices, net_info)

        return {
            "score":           max(0, score),
            "status":          "Sécurisé"      if score >= 80
                               else ("À améliorer" if score >= 50 else "Critique"),
            "issues":          issues,
            "recommendations": recommendations,
            "devices_count":   len(devices)
        }

    # ─── RECOMMANDATIONS (inchangées) ─────────────────────────────
    def _generate_recommendations(self, issues: list, devices: list, net_info: dict) -> list:
        recs       = []
        categories = {i["category"] for i in issues}

        if "Segmentation" in categories or len(devices) > 5:
            recs.append({
                "priority": 1, "title": "Mettre en place des VLANs",
                "effort": "Moyen", "impact": "Très élevé", "icon": "🔀",
                "description": "Séparez votre réseau en zones isolées :",
                "steps": [
                    "VLAN 10 — Postes de travail (192.168.10.0/24)",
                    "VLAN 20 — Serveurs et NAS (192.168.20.0/24)",
                    "VLAN 30 — IoT & appareils connectés (192.168.30.0/24)",
                    "VLAN 40 — Réseau invités isolé (192.168.40.0/24)",
                    "Règles firewall inter-VLAN : IoT bloqué vers les autres VLANs"
                ],
                "tools": ["Ubiquiti UniFi", "pfSense", "OPNsense", "Switch manageable"]
            })

        if "WiFi" in categories:
            recs.append({
                "priority": 2, "title": "Désactiver WPS sur le routeur",
                "effort": "Faible", "impact": "Élevé", "icon": "📡",
                "description": "WPS est vulnérable à la Pixie Dust attack :",
                "steps": [
                    "Accédez à l'interface admin du routeur (192.168.1.1 ou 192.168.0.1)",
                    "Cherchez 'WPS' dans les paramètres WiFi",
                    "Désactivez complètement WPS",
                    "Vérifiez que le mode 'WPS Push Button' est désactivé",
                    "Redémarrez le routeur pour appliquer"
                ],
                "tools": ["Interface web du routeur", "Application mobile opérateur"]
            })

        recs.append({
            "priority": 3, "title": "Passer en WPA3 ou WPA2-AES minimum",
            "effort": "Faible", "impact": "Élevé", "icon": "🔒",
            "description": "Le chiffrement WiFi protège les communications sans fil :",
            "steps": [
                "Ouvrez l'interface admin du routeur",
                "Désactivez WEP et WPA-TKIP (obsolètes et cassables)",
                "Activez WPA3 si disponible, sinon WPA2-AES minimum",
                "Utilisez un mot de passe WiFi de 20+ caractères aléatoires",
                "Changez le SSID par défaut"
            ],
            "tools": ["Interface admin routeur", "Bitwarden (générateur de mots de passe)"]
        })

        if "Protocole" in categories or "Accès distant" in categories:
            recs.append({
                "priority": 4, "title": "Fermer les ports et protocoles dangereux",
                "effort": "Moyen", "impact": "Critique", "icon": "🚪",
                "description": "Des services non sécurisés sont exposés sur votre réseau :",
                "steps": [
                    "Remplacer Telnet (23) par SSH avec clés",
                    "Remplacer FTP (21) par SFTP ou SCP",
                    "Restreindre RDP (3389) via VPN uniquement",
                    "Tunneliser VNC via SSH",
                    "Bloquer SMB (445) sur le périmètre réseau"
                ],
                "tools": ["nmap -sV", "OpenSSH", "WireGuard VPN", "Windows Firewall"]
            })

        if "DNS" in categories:
            recs.append({
                "priority": 5, "title": "Déployer un filtre DNS (Pi-hole / AdGuard Home)",
                "effort": "Faible", "impact": "Moyen", "icon": "🛡️",
                "description": "Un DNS filtering local bloque les domaines malveillants :",
                "steps": [
                    "Installer Pi-hole sur un Raspberry Pi ou une VM légère",
                    "Pointer le DNS du routeur vers l'IP du Pi-hole",
                    "Activer les listes de blocage : Steven Black, Firebog, OISD",
                    "Activer DNS-over-HTTPS (DoH) via cloudflared",
                    "Superviser les requêtes DNS pour détecter des anomalies C2"
                ],
                "tools": ["Pi-hole (gratuit)", "AdGuard Home (gratuit)", "Raspberry Pi 4"]
            })

        if "Inventaire" in categories or len(devices) > 3:
            recs.append({
                "priority": 6, "title": "Activer le filtrage MAC et inventaire réseau",
                "effort": "Moyen", "impact": "Moyen", "icon": "📋",
                "description": "Contrôlez exactement qui se connecte à votre réseau :",
                "steps": [
                    "Lister toutes les adresses MAC autorisées dans le routeur",
                    "Activer le filtrage MAC",
                    "Activer les notifications de nouvelle connexion WiFi",
                    "Créer un réseau invité séparé",
                    "Revoir la liste des appareils connectés chaque mois"
                ],
                "tools": ["Interface routeur", "Fing App", "Angry IP Scanner"]
            })

        recs.append({
            "priority": 7, "title": "Déployer un firewall et monitoring réseau",
            "effort": "Élevé", "impact": "Très élevé", "icon": "🔥",
            "description": "Protégez et surveillez votre réseau en temps réel :",
            "steps": [
                "Remplacer le routeur opérateur par pfSense ou OPNsense",
                "Activer l'IDS/IPS Suricata pour détecter les intrusions",
                "Configurer des alertes email sur activités suspectes",
                "Centraliser les logs réseau (Graylog ou ELK Stack)",
                "Effectuer un scan Nessus/OpenVAS mensuel"
            ],
            "tools": ["pfSense (gratuit)", "OPNsense (gratuit)", "Suricata IDS", "Graylog"]
        })

        return sorted(recs, key=lambda x: x["priority"])

    # ─── TOPOLOGIE ────────────────────────────────────────────────
    def _build_topology(self, scan_result: dict) -> dict:
        devices = scan_result.get("devices", [])
        gateway = scan_result.get("network_info", {}).get("gateway", "")
        local   = scan_result.get("network_info", {}).get("local_ip", "")
        nodes, edges = [], []

        nodes.append({"id": "gateway", "label": f"🌐 Box\n{gateway}", "type": "gateway", "ip": gateway})
        nodes.append({"id": "aria",    "label": f"🛡️ ARIA\n{local}",  "type": "aria",    "ip": local})
        edges.append({"from": "gateway", "to": "aria"})

        for d in devices:
            if d["ip"] in (gateway, local):
                continue
            node_id = d["ip"].replace(".", "_")
            ports   = scan_result.get("open_ports", {}).get(d["ip"], [])
            label   = f"{d['type']}\n{d['ip']}"
            if d["hostname"] != d["ip"]:
                label += f"\n{d['hostname'][:15]}"
            nodes.append({
                "id": node_id, "label": label, "type": d["type"],
                "ip": d["ip"], "open_ports": len(ports),
                "mac": d["mac"], "vendor": d["vendor"]
            })
            edges.append({"from": "gateway", "to": node_id})

        return {"nodes": nodes, "edges": edges}

    # ─── RÉSUMÉ ───────────────────────────────────────────────────
    def _build_summary(self, result: dict) -> dict:
        devices   = result.get("devices", [])
        security  = result.get("security", {})
        all_ports = result.get("open_ports", {})
        all_open  = [p for ports in all_ports.values() for p in ports]
        risky     = [p for p in all_open if "RISQUE" in p.get("risk", "")]

        return {
            "appareils_détectés": len(devices),
            "ports_ouverts":      len(all_open),
            "ports_à_risque":     len(risky),
            "score_sécurité":     security.get("score", 0),
            "statut":             security.get("status", "Inconnu"),
            "problèmes_détectés": len(security.get("issues", []))
        }

    # ─── SAUVEGARDE ───────────────────────────────────────────────
    def _save_scan(self, result: dict):
        os.makedirs("data/scans", exist_ok=True)
        fname = f"data/scans/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"✅ Scan sauvegardé : {fname}")

    def get_last_scan(self) -> dict | None:
        scan_dir = "data/scans"
        if not os.path.exists(scan_dir):
            return None
        files = sorted(os.listdir(scan_dir))
        if not files:
            return None
        with open(f"{scan_dir}/{files[-1]}") as f:
            return json.load(f)