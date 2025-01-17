import hashlib

# Fonction pour calculer le hachage SHA-256
def calculate_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Erreur lors du calcul du hachage pour {file_path}: {e}")
        return None

# Chemin du fichier à tester
file_path = r"C:\Users\MOHAMED HASSAN\OneDrive - FIVE PIZZA ORIGINAL\Documents\Bureau\virus\eicar.com.txt"

# Hachage attendu
expected_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Calculer le hachage et comparer
file_hash = calculate_hash(file_path)
print(f"Hachage calculé : {file_hash}")
if file_hash == expected_hash:
    print("Fichier détecté comme menace (EICAR Test File).")
else:
    print("Aucune menace détectée.")
