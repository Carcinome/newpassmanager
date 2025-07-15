import json
import os

# chemin vers le fichier de stockage du master password
MASTER_PASSWORD_FILE = "data/master.json"

def init_storage():
    """Créer le fichier master.json si celui-ci n'existe pas."""
    if not os.path.exists(MASTER_PASSWORD_FILE):
        print("Aucun mot de passe maître trouvé.")
        master = input("Créez votre mot de passe maître : ")
        with open(MASTER_PASSWORD_FILE, "w") as f:
            json.dump({"master_password": master}, f)
        print("Le mot de passe maître est enregistré.")
    else:
        with open(MASTER_PASSWORD_FILE, "r") as f:
            data = json.load(f)
        trial = input("Entrez le mot de passe maître : ")
        if trial == data["master_password"]:
            print("access granted.")
        else:
            print("access denied.")

if __name__ == "__main__":
    init_storage()