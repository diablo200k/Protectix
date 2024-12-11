import os
import hashlib
import json

# Charger la base de signatures
SIGNATURES_FILE = "data/signatures.json"

def load_signatures():
    """Charge la base de signatures depuis un fichier JSON."""
    try:
        with open(SIGNATURES_FILE, "r") as file:
            signatures = json.load(file)
        return signatures
    except FileNotFoundError:
        print(f"Erreur : Le fichier {SIGNATURES_FILE} est introuvable.")
        return {}

# Générer le hash d'un fichier
def calculate_file_hash(file_path, hash_algorithm="sha256"):
    """Calcule le hash d'un fichier en utilisant l'algorithme spécifié."""
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Erreur lors du calcul du hash pour {file_path} : {e}")
        return None

# Scanner un dossier
def scan_folder(folder_path):
    """Scanne un dossier et compare les fichiers avec la base de signatures."""
    signatures = load_signatures()
    if not signatures:
        print("La base de signatures est vide ou introuvable.")
        return []

    threats_detected = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)

            if file_hash in signatures:
                threats_detected.append({"file": file_path, "threat": signatures[file_hash]})

    return threats_detected
