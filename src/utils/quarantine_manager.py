import os
import shutil

QUARANTINE_FOLDER = "data/quarantine"

def ensure_quarantine_folder_exists():
    """Crée le dossier de quarantaine s'il n'existe pas."""
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)

def move_to_quarantine(file_path):
    """Déplace un fichier dans le dossier de quarantaine."""
    ensure_quarantine_folder_exists()
    try:
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_FOLDER, file_name)
        shutil.move(file_path, quarantine_path)
        return quarantine_path
    except Exception as e:
        print(f"Erreur lors du déplacement de {file_path} en quarantaine : {e}")
        return None

def list_quarantined_files():
    """Liste tous les fichiers présents dans le dossier de quarantaine."""
    ensure_quarantine_folder_exists()
    return os.listdir(QUARANTINE_FOLDER)

def restore_file(file_name, original_path):
    """Restaure un fichier depuis la quarantaine vers son emplacement d'origine."""
    try:
        file_path = os.path.join(QUARANTINE_FOLDER, file_name)
        shutil.move(file_path, original_path)
        return True
    except Exception as e:
        print(f"Erreur lors de la restauration de {file_name} : {e}")
        return False

def delete_file(file_name):
    """Supprime un fichier de la quarantaine."""
    try:
        file_path = os.path.join(QUARANTINE_FOLDER, file_name)
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Erreur lors de la suppression de {file_name} : {e}")
        return False
