# 📘 Pense-bête Python & Projet Password Manager

## 1. Les bases de Python

### 1.1. Qu’est-ce qu’un script Python ?
- Un **script Python** est un fichier texte qui contient du code écrit en Python (`.py`).
- Ce fichier peut être exécuté par l’interpréteur Python (`python3 mon_fichier.py`).

### 1.2. Qu’est-ce qu’une fonction ?
- Une **fonction** est un bloc de code réutilisable.
- Elle se définit avec `def`, prend éventuellement des paramètres, et peut retourner une valeur.

Exemple :
```python
def addition(a, b):
    return a + b

print(addition(2, 3))  # 5
```

### 1.3. Qu’est-ce qu’une classe ?
- Une **classe** est un modèle qui permet de créer des objets.
- Les objets regroupent des **données** (attributs) et des **comportements** (méthodes).

Exemple :
```python
class Voiture:
    def __init__(self, marque):
        self.marque = marque
    
    def klaxonner(self):
        print(f"La voiture {self.marque} klaxonne !")

v = Voiture("Renault")
v.klaxonner()  # La voiture Renault klaxonne !
```

### 1.4. Qu’est-ce qu’un module ?
- Un **module** est simplement un fichier Python (`.py`) que l’on peut importer.
- Exemple : `import math` permet d’utiliser `math.sqrt(9)`.

---

## 2. Notre projet Password Manager

### 2.1. Organisation des fichiers
```
newpassmanager/
│── main.py              # Point d’entrée du programme
│── gui.py               # Gestion de l’interface graphique (Tkinter)
│── utils.py             # Fonctions de sécurité (hash, dérivation, chiffrement)
│── crypto.py            # Extension possible pour gestion de clés
│── model.py             # Modèle : Vault (coffre) et Entry (entrée)
│── __init__.py          # Rassemble les imports du package vault
│── data/
    │── primary_password.json   # Stocke le mot de passe principal (format sécurisé)
    │── vault.enc               # Vault chiffré avec Fernet
    │── salt.bin                # Salt unique pour dérivation
```

---

## 3. Le cœur du projet : Sécurité

### 3.1. Salt (sel cryptographique)
- **But :** rendre chaque dérivation de mot de passe unique, même si deux utilisateurs ont le même mot de passe.
- **Caractéristiques :**
  - Stocké dans `salt.bin`
  - Pas secret, mais indispensable pour la dérivation.
  - Exemple : `os.urandom(16)` → génère 16 octets aléatoires.

### 3.2. PBKDF2HMAC
- **But :** transformer le mot de passe principal en une clé de chiffrement robuste.
- **Paramètres :**
  - Hash : SHA256
  - Longueur : 32 octets
  - Itérations : 200 000 (ralentit les attaques par force brute)

Exemple tiré de `utils.py` :
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=200_000,
)
```

### 3.3. Fernet
- **But :** chiffrer/déchiffrer de manière simple et sûre.
- Utilise la clé dérivée par PBKDF2.
- Exemple :
```python
fernet = Fernet(b64_key)
token = fernet.encrypt(b"motdepasse123")
print(fernet.decrypt(token))  # b"motdepasse123"
```

---

## 4. Le modèle : Vault & Entry

### 4.1. Entry
- Une entrée correspond à un mot de passe enregistré.
- Champs :
  - `name` (nom unique, ex: "Gmail")
  - `website`
  - `username`
  - `password`
  - `tags`

### 4.2. Vault
- Le **Vault** est la mémoire centrale.
- Il contient toutes les entrées **en clair** tant que le programme est lancé.
- Il offre des méthodes CRUD :
  - **C**reate → `add_vault_entry`
  - **R**ead → `get_vault_entry`
  - **U**pdate → `update_vault_entry`
  - **D**elete → `delete_vault_entry`

---

## 5. L’interface graphique (Tkinter)

### 5.1. InitiatePrimaryWindow
- S’ouvre si aucun `primary_password.json` n’existe.
- Demande de créer et confirmer un mot de passe principal.
- Sauvegarde dans un fichier JSON sécurisé.

### 5.2. WindowLogin
- Demande le mot de passe principal existant.
- Vérifie grâce au `verifier` chiffré.
- Si bon : dérive la clé Fernet et ouvre le coffre (`vault.enc`).

### 5.3. MainWindow
- La fenêtre principale du gestionnaire.
- Affiche un tableau (Treeview) avec les colonnes :
  - entrée
  - site/app
  - utilisateur
  - mot de passe (masqué par défaut)
- Boutons disponibles :
  - **Add** → ajouter une entrée
  - **Edit** → modifier
  - **Delete** → supprimer
  - **Show** → afficher temporairement le mot de passe
  - **Copy** → copier dans le presse-papier

---

## 6. Exemple de flux complet

1. Lancer `main.py`
2. **Première fois :**
   - Création d’un mot de passe principal
   - Sauvegarde dans `primary_password.json` + génération `salt.bin`
3. **Connexion suivante :**
   - Vérification du mot de passe principal
   - Récupération de la clé Fernet
   - Chargement du coffre `vault.enc`
4. Ajout/modification/suppression d’entrées via la GUI
5. Sauvegarde automatique dans `vault.enc`

---

## 7. Questions & réponses (auto-test)

**Q1. Pourquoi utilise-t-on un `salt` ?**  
👉 Pour que deux utilisateurs ayant le même mot de passe génèrent des clés différentes, évitant les attaques par "rainbow tables".

**Q2. Quelle est la différence entre `Entry` et `Vault` ?**  
👉 `Entry` = une seule entrée (un compte avec mot de passe).  
👉 `Vault` = l’ensemble des entrées, avec des méthodes pour gérer les ajouts/suppressions/etc.

**Q3. Pourquoi le mot de passe principal n’est-il jamais stocké en clair ?**  
👉 Parce que seul un **verifier chiffré** est sauvegardé. On peut vérifier la validité du mot de passe sans jamais le conserver.

**Q4. Quelle est la fonction de `PBKDF2HMAC` ?**  
👉 Transformer un mot de passe faible (texte clair) en clé forte (octets aléatoires imprévisibles).
