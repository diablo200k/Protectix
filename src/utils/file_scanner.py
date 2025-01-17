import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor

# Générer un chemin absolu vers `signatures.json`
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SIGNATURE_FILE = os.path.join(BASE_DIR, "database", "signatures.json")


def load_signatures():
    """
    Charge les signatures depuis le fichier JSON.
    """
    try:
        with open(SIGNATURE_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Le fichier des signatures {SIGNATURE_FILE} est introuvable.")
    except json.JSONDecodeError as e:
        raise ValueError(f"Erreur de format JSON dans {SIGNATURE_FILE}: {e}")


def calculate_hash(file_path):
    """
    Calcule le hachage SHA-256 d'un fichier.
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Fichier introuvable : {file_path}")
        return None
    except Exception as e:
        print(f"Erreur lors du calcul du hachage pour {file_path}: {e}")
        return None


def detect_pattern(file_path, patterns):
    """
    Analyse un fichier pour détecter un motif spécifique.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            for signature in patterns:
                if "pattern" in signature and signature["pattern"] in content:
                    return {"file": file_path, "threat": signature["name"]}
        return None
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        return None


def scan_file(file_path, signatures):
    """
    Analyse un fichier unique pour détecter une menace.
    """
    try:
        # Vérification par hachage
        file_hash = calculate_hash(file_path)
        print(f"[DEBUG] Hachage pour {file_path}: {file_hash}")
        if file_hash:
            for signature in signatures:
                if "hash" in signature and signature["hash"] == file_hash:
                    print(f"[DEBUG] Menace détectée par hachage : {signature['name']}")
                    return {"file": file_path, "threat": signature["name"]}

        # Vérification par motifs
        return detect_pattern(file_path, signatures)
    except Exception as e:
        print(f"Erreur lors de l'analyse du fichier {file_path}: {e}")
        return None


def scan_directory(directory):
    """
    Scanne un dossier pour détecter les menaces en utilisant plusieurs threads.
    """
    signatures = load_signatures()
    threats = []
    files = []

    # Collecte des fichiers dans le dossier
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    if not files:
        print(f"Aucun fichier trouvé dans le dossier : {directory}")
        return []

    # Analyse parallèle des fichiers
    with ThreadPoolExecutor() as executor:
        results = executor.map(lambda f: scan_file(f, signatures), files)
        threats = [result for result in results if result]

    return threats
