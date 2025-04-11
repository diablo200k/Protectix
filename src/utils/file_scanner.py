import os
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional, Callable
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
logger = logging.getLogger("scan")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('[%(levelname)s] %(message)s')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

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
                    logger.warning("Signature invalide ligne %d: %s", line_number, line)
                    continue
                valid_hashes.add(line)

            if not valid_hashes:
                logger.error("Aucune signature valide trouvée dans le fichier")

            eicar_hash = "44d88612fea8a8f36de82e1278abb02f"
            if eicar_hash not in valid_hashes:
                logger.warning("Signature EICAR manquante dans la base de données")

            logger.info("%d signatures MD5 chargées", len(valid_hashes))
            return valid_hashes

    except Exception as error:
        logger.error("Erreur de chargement des signatures : %s", str(error))
        return set()

def calculate_md5(file_path: str) -> Optional[str]:
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(MD5_BLOCK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as error:
        logger.error("Erreur de calcul MD5 pour %s: %s", file_path, str(error))
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
            logger.warning("VirusTotal: réponse %d pour hash %s", response.status_code, md5_hash)
            return None
    except Exception as e:
        logger.error("Erreur lors de la requête VirusTotal pour %s: %s", md5_hash, str(e))
        return None

def scan_file(file_path: str, signatures: Set[str], index: int, total: int, progress_callback: Optional[Callable] = None) -> Optional[Dict]:
    if not os.path.isfile(file_path):
        logger.warning("[%d/%d] %s n'est pas un fichier valide", index, total, file_path)
        return None

    try:
        logger.info("[%d/%d] Analyse : %s", index, total, file_path)
        if progress_callback:
            progress_callback(index, total, file_path)

        file_hash = calculate_md5(file_path)
        if not file_hash:
            return None

        if file_hash in signatures:
            logger.warning("[%d/%d] Menace détectée localement : %s", index, total, file_path)
            try:
                quarantine_path = move_to_quarantine(file_path)
                return {
                    'file': file_path,
                    'hash': file_hash,
                    'source': "local",
                    'quarantine': quarantine_path
                }
            except Exception as error:
                logger.error("Échec quarantaine pour %s: %s", file_path, error)
                return None

        vt_result = check_virustotal(file_hash)
        if vt_result and (vt_result["malicious"] > 0 or vt_result["suspicious"] > 0):
            logger.warning("[%d/%d] Menace détectée via VirusTotal : %s", index, total, file_path)
            return {
                'file': file_path,
                'hash': file_hash,
                'source': "virustotal",
                'malicious': vt_result["malicious"],
                'suspicious': vt_result["suspicious"]
            }

        logger.info("[%d/%d] OK : %s", index, total, file_path)
        return None

    except Exception as error:
        logger.error("Échec analyse de %s: %s", file_path, error)
        return None

def scan_directory(directory, progress_callback: Optional[Callable] = None):
    logger.info("[DEBUG] 🔎 Scan en cours pour : %s", directory)

    signatures = load_md5_signatures()
    if not signatures:
        logger.error("[ERREUR] ❌ Aucune signature chargée. Vérifiez `Hashes.txt`.")
        return []

    threats = []
    files = []

    if os.path.isfile(directory):
        logger.info("[DEBUG] 🔍 Fichier unique à analyser : %s", directory)
        files = [directory]
    elif os.path.isdir(directory):
        logger.info("[DEBUG] 🔍 Scan du dossier : %s", directory)
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                files.append(file_path)
    else:
        logger.error("[ERREUR] ❌ Le chemin %s n'est ni un fichier ni un répertoire.", directory)
        return []

    if not files:
        logger.info("[INFO] ❌ Aucun fichier trouvé dans %s", directory)
        return []

    total_files = len(files)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_file, file, signatures, idx + 1, total_files, progress_callback): file
            for idx, file in enumerate(files)
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                threats.append(result)

    elapsed_time = time.time() - start_time
    logger.info("⏱️ Temps total de scan : %.2f secondes", elapsed_time)
    logger.info("✅ Scan terminé. Menaces détectées : %d", len(threats))
    return threats
