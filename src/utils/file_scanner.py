import os
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional
from utils.quarantine_manager import move_to_quarantine
import requests

# Configuration des constantes
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SIGNATURE_FILE = os.path.join(BASE_DIR, "database", "Hashes.txt")
MD5_BLOCK_SIZE = 131072  # 128 KB pour meilleures performances
MAX_WORKERS = os.cpu_count() or 4
VIRUSTOTAL_API_KEY = "77109c720de712d2c8428753f150ee82a13eac1b4f1a050c8c71605a83d20a80"
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

def load_md5_signatures() -> Set[str]:
    try:
        if not os.path.exists(SIGNATURE_FILE):
            raise FileNotFoundError(f"Fichier de signatures introuvable : {SIGNATURE_FILE}")

        with open(SIGNATURE_FILE, 'r', encoding='utf-8') as file:
            valid_hashes = set()
            for line_number, line in enumerate(file, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if len(line) != 32 or not all(c in '0123456789abcdef' for c in line):
                    logging.warning("Signature invalide ligne %d: %s", line_number, line)
                    continue
                valid_hashes.add(line)

            if not valid_hashes:
                logging.error("Aucune signature valide trouvée dans le fichier")

            eicar_hash = "44d88612fea8a8f36de82e1278abb02f"
            if eicar_hash not in valid_hashes:
                logging.warning("Signature EICAR manquante dans la base de données")

            logging.info("%d signatures MD5 chargées", len(valid_hashes))
            return valid_hashes

    except Exception as error:
        logging.error("Erreur de chargement des signatures : %s", str(error))
        return set()

def calculate_md5(file_path: str) -> Optional[str]:
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(MD5_BLOCK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as error:
        logging.error("Erreur de calcul MD5 pour %s: %s", file_path, str(error))
        return None

def check_virustotal(md5_hash: str) -> Optional[Dict]:
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url = f"{VT_BASE_URL}{md5_hash}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {"malicious": malicious, "suspicious": suspicious, "source": "VirusTotal"}
        else:
            logging.warning("VirusTotal: réponse %d pour hash %s", response.status_code, md5_hash)
            return None
    except Exception as e:
        logging.error("Erreur lors de la requête VirusTotal pour %s: %s", md5_hash, str(e))
        return None

def scan_file(file_path: str, signatures: Set[str]) -> Optional[Dict]:
    if not os.path.isfile(file_path):
        logging.warning("%s n'est pas un fichier valide", file_path)
        return None

    try:
        file_hash = calculate_md5(file_path)
        if not file_hash:
            return None

        if file_hash in signatures:
            logging.warning("Menace détectée localement : %s", file_path)
            try:
                quarantine_path = move_to_quarantine(file_path)
                return {
                    'file': file_path,
                    'hash': file_hash,
                    'source': "local",
                    'quarantine': quarantine_path
                }
            except Exception as error:
                logging.error("Échec quarantaine pour %s: %s", file_path, error)
                return None

        # Vérification avec VirusTotal
        vt_result = check_virustotal(file_hash)
        if vt_result and (vt_result["malicious"] > 0 or vt_result["suspicious"] > 0):
            logging.warning("Menace détectée via VirusTotal : %s", file_path)
            return {
                'file': file_path,
                'hash': file_hash,
                'source': "virustotal",
                'malicious': vt_result["malicious"],
                'suspicious': vt_result["suspicious"]
            }

        return None

    except Exception as error:
        logging.error("Échec analyse de %s: %s", file_path, error)
        return None

def scan_directory(directory):
    print(f"[DEBUG] 🔎 Scan en cours pour : {directory}")

    signatures = load_md5_signatures()
    if not signatures:
        print("[ERREUR] ❌ Aucune signature chargée. Vérifiez `Hashes.txt`.")
        return []

    threats = []
    files = []

    if os.path.isfile(directory):
        print(f"[DEBUG] 🔍 Fichier unique à analyser : {directory}")
        files = [directory]
    elif os.path.isdir(directory):
        print(f"[DEBUG] 🔍 Scan du dossier : {directory}")
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                print(f"[DEBUG] 📂 Fichier trouvé : {file_path}")
                files.append(file_path)
    else:
        print(f"[ERREUR] ❌ Le chemin {directory} n'est ni un fichier ni un répertoire.")
        return []

    if not files:
        print(f"[INFO] ❌ Aucun fichier trouvé dans {directory}")
        return []

    with ThreadPoolExecutor() as executor:
        results = executor.map(lambda f: scan_file(f, signatures), files)
        threats = [result for result in results if result]

    print(f"[DEBUG] 🔎 Scan terminé. Menaces détectées : {len(threats)}")
    return threats

if __name__ == "__main__":
    try:
        logging.info("🚀 Démarrage Protectix Antivirus")
        target_dir = input("Entrez le chemin à analyser: ").strip()

        if not os.path.exists(target_dir):
            raise ValueError("Chemin spécifié introuvable")

        scan_results = scan_directory(target_dir)

        if scan_results:
            logging.warning("🚨 %d menaces détectées:", len(scan_results))
            for threat in scan_results:
                logging.warning("• %s (MD5: %s)", threat['file'], threat['hash'])
        else:
            logging.info("✅ Aucune menace détectée")

    except Exception as error:
        logging.critical("ERREUR CRITIQUE: %s", error)
    finally:
        logging.info("🏁 Fin d'exécution")
