# KAGEsniffer
**Développé par KOUAKOU GUY (Pseudo: KAGEHACKER)**  
**Date : Mars 2025**

Un sniffer réseau avancé avec interface graphique, détection d’anomalies et GeoIP via GeoLite2-City.mmdb.

## Fonctionnalités
1. **Capture réseau** :
   - Temps réel sur une interface (ex: eth0, wlan0).
   - Filtrage : HTTP (port 80), DNS (port 53), FTP (port 21).
2. **Analyse** :
   - IPs source/destination.
   - URLs (HTTP), domaines (DNS).
   - GeoIP : ville, pays via GeoLite2-City.mmdb.
3. **Détection d’anomalies** :
   - **Mots-clés sensibles** : "admin", "login", "secret", "password".
   - **Requêtes répétitives** : >10 requêtes par IP en 60s.
4. **Interface graphique** :
   - Tableau avec alertes en rouge.
   - Boutons : Lancer, Arrêter, Exporter Logs, Effacer.
   - Barre de statut : paquets capturés, alertes.
5. **Logs** :
   - Fichier : `traffic_log.txt`.
   - Rotation : 10MB, 5 backups.

## Prérequis
- Python 3.8+
- Droits root (capture réseau).
- `GeoLite2-City.mmdb` dans le dossier racine.
- Système avec libpcap (installé via `sudo apt install libpcap-dev` sur Linux).

## Installation
veillez dezipper GeoLite2-City.mmdb.zip puis l'enregistrez dans le dossier KAGEsniffer
1. Clonez le dépôt :
   ```bash
   git clone https://github.com/KAGEHACKER/KAGEsniffer.git
   cd KAGEsniffer

   Comment lancer le programme
   pip install -r requirements.txt
   python3 sniffer.py
