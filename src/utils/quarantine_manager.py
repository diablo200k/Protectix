import os
import shutil

# Définition du dossier de quarantaine en utilisant un chemin absolu
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data"))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")

def move_to_quarantine(file_path):
    """
    Déplace un fichier détecté comme malveillant vers le dossier de quarantaine.
    :param file_path: Chemin complet du fichier à déplacer
    :return: Message indiquant le résultat de l'opération
    """
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    try:
        destination = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
        shutil.move(file_path, destination)
        return f"Fichier déplacé en quarantaine : {file_path}"
    except Exception as e:
        return f"Erreur lors du déplacement en quarantaine : {e}"

def list_quarantine():
    """
    Retourne une liste des fichiers présents dans le dossier de quarantaine.
    :return: Liste des noms de fichiers en quarantaine
    """
    if not os.path.exists(QUARANTINE_DIR):
        return []
    return os.listdir(QUARANTINE_DIR)

def restore_file(file_name):
    """
    Restaure un fichier depuis la quarantaine vers son emplacement d'origine (le répertoire courant).
    :param file_name: Nom du fichier à restaurer
    :return: Message indiquant le résultat de l'opération
    """
    file_path = os.path.join(QUARANTINE_DIR, file_name)
    if os.path.exists(file_path):
        try:
            shutil.move(file_path, os.getcwd())  # Restaure dans le répertoire courant
            return f"Fichier restauré : {file_name}"
        except Exception as e:
            return f"Erreur lors de la restauration : {e}"
    return f"Fichier introuvable dans la quarantaine : {file_name}"

def delete_from_quarantine(file_name):
    """
    Supprime définitivement un fichier du dossier de quarantaine.
    :param file_name: Nom du fichier à supprimer
    :return: Message indiquant le résultat de l'opération
    """
    file_path = os.path.join(QUARANTINE_DIR, file_name)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return f"Fichier supprimé définitivement : {file_name}"
        except Exception as e:
            return f"Erreur lors de la suppression : {e}"
    return f"Fichier introuvable dans la quarantaine : {file_name}"
