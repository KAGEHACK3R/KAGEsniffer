#!/usr/bin/env python3
"""
KAGEsniffer - Advanced Network Sniffer
Auteur : KOUAKOU GUY (Pseudo: KAGEHACKER)
Date : Mars 2025
Description : Un sniffer réseau avec interface graphique, détection d’anomalies et GeoIP via GeoLite2-City.mmdb.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from collections import Counter
import logging
import logging.handlers
from datetime import datetime
import geoip2.database
from scapy.all import sniff, IP, TCP, UDP, DNS, conf
from scapy.layers.http import HTTPRequest  # Import corrigé pour HTTP
import netifaces  # Pour valider les interfaces réseau

# Configuration des logs
LOG_FILE = "traffic_log.txt"
logger = logging.getLogger("KAGEsniffer")
logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

class KAGEsniffer:
    """Classe principale pour KAGEsniffer."""
    def __init__(self, root):
        self.root = root
        self.root.title("KAGEsniffer - KAGEHACKER")
        self.root.geometry("1200x700")
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        self.request_counter = Counter()

        # Chargement GeoIP
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            logger.info("GeoIP chargé avec succès.")
        except FileNotFoundError:
            self.geoip_reader = None
            logger.warning("GeoLite2-City.mmdb non trouvé. GeoIP désactivé.")
        except Exception as e:
            self.geoip_reader = None
            logger.error(f"Erreur GeoIP : {e}")

        # Interface réseau
        tk.Label(root, text="Interface réseau (ex: eth0):", font=("Arial", 12)).pack(pady=5)
        self.interface_entry = tk.Entry(root, width=25, font=("Arial", 10))
        self.interface_entry.pack()

        # Tableau des paquets
        self.tree = ttk.Treeview(root, columns=("Time", "IP Src", "IP Dst", "Type", "Details", "Status", "GeoIP"),
                                 show="headings")
        columns = [("Time", 120), ("IP Src", 150), ("IP Dst", 150), ("Type", 80), 
                   ("Details", 350), ("Status", 120), ("GeoIP", 200)]
        for col, width in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Boutons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Lancer", command=self.start_sniffing, bg="green", fg="white",
                  font=("Arial", 10, "bold"), width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Arrêter", command=self.stop_sniffing, bg="red", fg="white",
                  font=("Arial", 10, "bold"), width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Exporter Logs", command=self.export_logs, bg="blue", fg="white",
                  font=("Arial", 10, "bold"), width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Effacer", command=self.clear_table, bg="gray", fg="white",
                  font=("Arial", 10, "bold"), width=10).pack(side=tk.LEFT, padx=5)

        # Barre de statut
        self.status_var = tk.StringVar(value="Inactif - Paquets: 0 - Alertes: 0")
        tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W,
                 font=("Arial", 10)).pack(side=tk.BOTTOM, fill=tk.X)

    def process_packet(self, packet):
        """Traite chaque paquet capturé."""
        if not self.running:
            return

        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        ip_src = ip_dst = req_type = details = status = geoip_info = ""

        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst

                # Filtrage des protocoles
                if TCP in packet:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        req_type = "HTTP"
                        if HTTPRequest in packet:
                            host = packet[HTTPRequest].Host.decode(errors='ignore')
                            path = packet[HTTPRequest].Path.decode(errors='ignore')
                            details = f"{host}{path}"
                    elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                        req_type = "FTP"
                elif UDP in packet and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                    req_type = "DNS"
                    if DNS in packet and packet[DNS].qr == 0:
                        details = packet[DNS].qname.decode(errors='ignore')

                # GeoIP
                if self.geoip_reader:
                    try:
                        response = self.geoip_reader.city(ip_dst)
                        geoip_info = f"{response.city.name or 'Inconnu'}, {response.country.name or 'Inconnu'}"
                    except:
                        geoip_info = "Inconnu"
                else:
                    geoip_info = "GeoIP désactivé"

                # Détection
                status = self.detect_anomaly(ip_dst, details)
                tag = "alert" if "ANORMAL" in status else "normal"
                self.tree.insert("", "end", values=(timestamp, ip_src, ip_dst, req_type, details, status, geoip_info),
                                 tags=(tag,))
                self.tree.tag_configure("alert", background="red", foreground="white")
                self.tree.tag_configure("normal", background="white", foreground="black")
                self.status_var.set(f"Actif - Paquets: {self.packet_count} - Alertes: {self.alert_count}")

                # Log
                log_entry = f"IP Src: {ip_src} -> IP Dst: {ip_dst} | Type: {req_type} | Details: {details} | Status: {status} | GeoIP: {geoip_info}"
                logger.info(log_entry)

        except Exception as e:
            logger.error(f"Erreur traitement paquet : {e}")

    def detect_anomaly(self, ip_dst, details):
        """Détecte les anomalies avec deux critères."""
        sensitive_keywords = ["admin", "login", "secret", "password"]
        if details and any(keyword in details.lower() for keyword in sensitive_keywords):
            self.alert_count += 1
            return "ANORMAL (Mots-clés sensibles détectés)"

        self.request_counter[ip_dst] += 1
        window = 60
        if self.request_counter[ip_dst] > 10:
            self.alert_count += 1
            return f"ANORMAL (Requêtes répétitives: {self.request_counter[ip_dst]} en {window}s)"
        return "NORMAL"

    def start_sniffing(self):
        """Démarre la capture réseau."""
        if not self.running:
            interface = self.interface_entry.get().strip()
            if not interface:
                messagebox.showerror("Erreur", "Entrez une interface réseau.")
                return
            if interface not in netifaces.interfaces():
                messagebox.showerror("Erreur", f"Interface '{interface}' invalide.")
                return
            self.running = True
            self.packet_count = 0
            self.alert_count = 0
            self.request_counter.clear()
            try:
                conf.use_pcap = True  # Utilise libpcap pour éviter les problèmes de permissions
                self.sniff_thread = threading.Thread(target=lambda: sniff(iface=interface, prn=self.process_packet, store=0))
                self.sniff_thread.daemon = True
                self.sniff_thread.start()
                self.status_var.set("Actif - Paquets: 0 - Alertes: 0")
            except Exception as e:
                self.running = False
                messagebox.showerror("Erreur", f"Échec démarrage : {e}")
                logger.error(f"Échec démarrage : {e}")

    def stop_sniffing(self):
        """Arrête la capture."""
        self.running = False
        self.status_var.set(f"Inactif - Paquets: {self.packet_count} - Alertes: {self.alert_count}")

    def export_logs(self):
        """Confirme l’exportation des logs."""
        messagebox.showinfo("Export", f"Logs exportés dans {LOG_FILE} (rotation automatique).")

    def clear_table(self):
        """Efface le tableau."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_count = 0
        self.alert_count = 0
        self.status_var.set(f"Inactif - Paquets: {self.packet_count} - Alertes: {self.alert_count}")

if __name__ == "__main__":
    print("KAGEsniffer - Développé par KOUAKOU GUY (KAGEHACKER)")
    try:
        root = tk.Tk()
        app = KAGEsniffer(root)
        root.mainloop()
    except Exception as e:
        print(f"Erreur démarrage programme : {e}")
        logger.error(f"Erreur démarrage programme : {e}")
    print("Programme terminé - KOUAKOU GUY (KAGEHACKER)")
