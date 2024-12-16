import json
import os
import urllib.request

SIGNATURES_FILE = "data/signatures.json"

def load_signatures():
    """Charge la base de signatures existante."""
    if not os.path.exists(SIGNATURES_FILE):
        with open(SIGNATURES_FILE, "w") as file:
            json.dump({}, file)  # Crée un fichier vide si nécessaire
    with open(SIGNATURES_FILE, "r") as file:
        return json.load(file)

def save_signatures(signatures):
    """Sauvegarde la base de signatures dans un fichier."""
    with open(SIGNATURES_FILE, "w") as file:
        json.dump(signatures, file, indent=4)

def add_signature(hash_value, description):
    """Ajoute une nouvelle signature à la base locale."""
    signatures = load_signatures()
    signatures[hash_value] = description
    save_signatures(signatures)
    return True

def update_signatures_from_url(url):
    """
    Télécharge une base de signatures à partir d'une URL et fusionne avec la base locale.
    :param url: Lien vers le fichier JSON des signatures.
    :return: Nombre de signatures ajoutées.
    """
    try:
        response = urllib.request.urlopen(url)
        new_signatures = json.load(response)

        # Charger la base locale existante
        local_signatures = load_signatures()

        # Fusionner les bases
        merged_signatures = {**local_signatures, **new_signatures}

        # Sauvegarder la base fusionnée
        save_signatures(merged_signatures)

        # Retourner le nombre de nouvelles signatures ajoutées
        return len(merged_signatures) - len(local_signatures)
    except Exception as e:
        print(f"Erreur lors de la mise à jour : {e}")
        return 0
