Un peu de jargon :


* Static analyzer (analyseur statique) :
Un outil (comme pylint, mypy, flake8…) qui lit ton code sans l’exécuter, cherche des erreurs potentielles (typos, variables non définies, incohérences de types). Il t’alerte tôt, avant même que tu lances ton programme.


* Branche (if / else) :
Imagine un embranchement sur la route : le code suit soit le chemin “if” (si la condition est vraie), soit le “else” (sinon). Chaque branche peut avoir son propre return ou ses propres actions.


* return :
Mot-clé qui sort de la fonction et renvoie une valeur. Tout ce qui suit dans la fonction n’est pas exécuté.


* Exception (raise) :
Procédé pour signaler une erreur. Quand on lève (raise) une exception non attrapée, le programme s’arrête (à moins que tu gères l’exception ailleurs). C’est plus propre que de faire un exit(), car l’analyseur comprend qu’après un raise on ne continue pas.


* os.makedirs(..., exist_ok=True) :
Crée un dossier (et ses dossiers parents) si besoin sans crasher si le dossier existe déjà.


* json.dump / json.load :
Pour écrire/charger des données structurées (dictionnaires, listes) dans un fichier texte au format JSON.


Imports :

* os/json/base64 sont des bibliothèques intégrées à Python.
* cryptography est une lib tierce (installée avec pip install cryptography).

Constants :

* DATA_DIR est une chaîne indiquant le dossier
* Les deux os.path.join assemblent un chemin valide (Windows/Linux).

ensure_data_dir() :

* os.makedirs(..., exist_ok=True) crée le dossier récursivement (tous les dossiers parents nécessaires) et n’erreur pas si déjà créé.

Dérivation de clé :

* On utilise PBKDF2HMAC (KDF) pour transformer le mot de passe en une clé binaire fiable.
* Puis on encode cette clé en Base64 pour qu’elle soit compatible avec l’API Fernet.

Les bases de la syntaxe dans le jargon :

* Indentation : en Python, l’espacement en début de ligne (généralement 4 espaces) définit les blocs.
* Bloc : un groupe de lignes de code qui appartiennent à un même if, for, def, etc.
* if / else : ces deux mots-clés sont accrochés — ils forment un seul bloc alternatif. L’else doit toujours arriver juste après toutes les lignes indentées de l’if.
* : (deux-points) : indique à Python “attention, ce qui suit sur les lignes indentées forme un bloc”.


![img.png](env.work/dev_to_keep/load_password_explanation.png)

Classe :

* class Nom: définit un type personnalisé.
* def __init__(self, …): initialise l’état (attributs).
* Méthodes = fonctions dans la classe (1er paramètre : self).
* But : rassembler données + règles.
* Classe & indentation : une méthode doit être indentée dans la classe. Sinon, c’est une fonction libre.
* API stable = mêmes noms partout → moins d’erreurs.
* @classmethod : méthode appelable sur la classe (Vault.from_dict(...)) et qui retourne une instance.

Dataclass :

* @dataclass génère __init__ et d’autres méthodes utiles.
* Idéale pour des conteneurs (ex. Entry).

Séparation des responsabilités :

* vault/model.py : logique métier (CRUD, conversions).
* vault/storage.py : E/S chiffrées (un seul fichier).
* utils.py : dérivation de clé (mot de passe + salt), chemins, répertoires.
* gui.py : affichage + interactions, sans I/O directes ni crypto fine.

Crypto :

* PBKDF2HMAC (dans utils.py) : dérive une clé depuis (mot de passe + salt).
* Fernet : chiffre/déchiffre un bloc (coffre entier) et garantit l’intégrité.
* Salt : public, aléatoire, stocké dans data/salt.bin.

Patron de travail :

* GUI modifie Vault (RAM) → save_encrypted(...) (disque chiffré).
* Ré-ouverture : load_encrypted(...) → Vault (RAM).

JSON :

* json.dump(obj, f) → écrit un objet Python en texte JSON.
* json.load(f) → relit en dict.
* Toujours UTF‑8 pour sérénité.

IO fichiers :

* Texte : "w" / "r" ; Binaire : "wb" / "rb".
* Path(...).write_bytes() pour écrire des octets (chiffrés).