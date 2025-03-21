import requests
import hashlib

# Remplace ici par ta clé API
API_KEY = "77109c720de712d2c8428753f150ee82a13eac1b4f1a050c8c71605a83d20a80"
VT_URL = "https://www.virustotal.com/api/v3/files"

def calculate_sha256(file_path):
    """Calcule le hash SHA-256 d'un fichier."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Erreur de hachage du fichier {file_path}: {e}")
        return None

def scan_file_virustotal(file_path):
    """Analyse un fichier avec l'API de VirusTotal."""
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return None

    headers = {"x-apikey": API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

    if response.status_code == 200:
        result = response.json()
        if "data" in result and "attributes" in result["data"]:
            attributes = result["data"]["attributes"]
            return {
                "file": file_path,
                "hash": file_hash,
                "malicious": attributes["last_analysis_stats"]["malicious"],
                "suspicious": attributes["last_analysis_stats"]["suspicious"],
                "harmless": attributes["last_analysis_stats"]["harmless"],
                "undetected": attributes["last_analysis_stats"]["undetected"]
            }
    elif response.status_code == 404:
        print(f"[INFO] Fichier non trouvé sur VirusTotal : {file_path}.")
        return None
    else:
        print(f"[ERREUR] VirusTotal a retourné un code {response.status_code}: {response.text}")
        return None

def upload_file_virustotal(file_path):
    """Upload un fichier vers VirusTotal pour une analyse complète."""
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": (file_path, file)}
        response = requests.post(VT_URL, headers=headers, files=files)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f"[ERREUR] Impossible d'uploader {file_path} vers VirusTotal : {response.text}")
        return None
