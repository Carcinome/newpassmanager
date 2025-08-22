# 📘 CHEATSHEET — Password Manager Project

---

## 🔹 Python basics (rappels)

- **Fonction**
  ```python
  def my_function(arg1, arg2="default"):
      return arg1 + arg2
  ```
  ➝ Regrouper des instructions réutilisables, peut retourner une valeur.  

- **Classe**
  ```python
  class MyClass:
      def __init__(self, value):
          self.value = value
  ```
  ➝ Plan de construction d’objets. `__init__` est le constructeur.  

- **Méthode**
  ➝ Fonction définie *dans* une classe, prend toujours `self` comme premier paramètre.  

- **Module**
  ➝ Fichier `.py` importé dans d’autres fichiers. Exemple : `import utils`.

- **Package**
  ➝ Dossier contenant un `__init__.py`, permet d’organiser les modules.

---

## 🔹 Projet — Organisation des fichiers

- `main.py` → point d’entrée.  
- `gui.py` → interface Tkinter (fenêtres, boutons, Treeview).  
- `utils.py` → crypto, gestion du primary password, sauvegarde/lecture fichiers.  
- `model.py` → classes `Entry` et `Vault` (structure des données).  
- `crypto.py` → extension crypto (actuellement Fernet).  
- `__init__.py` → pour organiser le package `vault`.  
- `primary_password.json` → stocke le *verifier* chiffré.  
- `salt.bin` → sel utilisé pour dériver la clé.  
- `vault.enc` → coffre chiffré contenant les entrées.

---

## 🔹 Phase 0 — Mise en place
- Création des fichiers et séparation claire du code (GUI / utils / modèle).  
- `Entry` et `Vault` créés dans `model.py`.  
- GUI basique avec `Tkinter`.

---

## 🔹 Phase 1 — Sécurité et chiffrement

### 1.1 Mot de passe maître & KDF
- Utilisation de **PBKDF2HMAC (SHA-256)** avec sel aléatoire.  
- Le sel est sauvegardé dans `salt.bin`.  

### 1.2 Stockage sécurisé du mot de passe maître
- Vérificateur chiffré stocké dans `primary_password.json`.  
- Pas de stockage du mot de passe en clair.

### 1.3 Vérification
- `verify_primary_password_and_get_key` compare le mot de passe saisi avec le vérificateur chiffré.  

### 1.4 Coffre chiffré
- Sauvegarde dans `vault.enc` via Fernet.  
- `Vault` sait se convertir en dict et inversement.

### 1.5 Robustesse
- Gestion des exceptions (`InvalidToken`, erreurs d’E/S).  
- Messages clairs en cas de problème.

### 1.6 Logs
- `logger.info()` pour les actions normales (sauvegarde, ouverture).  
- `logger.error()` pour les erreurs.

---

## 🔹 Phase 2 — Expérience utilisateur (UX)

### 2.1 GUI ergonomique
- Fenêtres avec titre, taille fixée, redimensionnement activé.  
- `Treeview` ajustable.  

### 2.2 Messages améliorés
- `messagebox.showerror/showwarning/showinfo` pour feedback clair.  

### 2.3 Affichage temporaire mot de passe
- Bouton “Show password” → affiche pour `n` secondes, puis masque.  
- Utilisation de `after(ms, callback)` pour re-masquer.

### 2.4 Copie presse-papiers
- `clipboard_clear()` + `clipboard_append(password)`.  
- Effacement automatique après X secondes (`after`).  

### 2.5 Internationalisation (i18n)
- Fichier `i18n.py` avec `gettext`.  
- Proxy `_` (LazyTranslator) → permet de changer de langue sans tout ré-importer.  
- Fichiers `.po` / `.mo` dans `locales/<lang>/LC_MESSAGES/passman.mo`.  
- Langue réglée une seule fois dans `main.py` via `setup_language("fr")` ou `setup_language("en")`.

### 2.6 UX mini-boosts
- **Double-clic** sur une ligne = copie auto du mot de passe.  
- **Confirmation suppression** → `askyesno("Confirm", "Are you sure?")`.  
- **Status bar améliorée** avec helper `set_status(text, timeout)` → affiche un message et le fait disparaître après délai.  
- **Feedback unifié** (copy, show, delete → status bar).

---

## 🔹 Concepts clés (pédagogie)

- **after(ms, func)** → planifie une action différée (ici : effacer mot de passe ou message).  
- **Treeview**  
  - `insert("", "end", values=(...))` → ajoute une ligne.  
  - `selection()` → récupère la ligne sélectionnée.  
  - `identify_row(event.y)` → récupérer la ligne cliquée (utile pour double-clic).  
- **Messagebox**  
  - `showerror`, `showinfo`, `showwarning`.  
  - `askyesno` → retourne True/False.  
- **Clipboard**  
  - `clipboard_clear()`, `clipboard_append(text)`.  
  - Attention aux erreurs `TclError` si le système refuse l’accès.

---

## 🔹 Résumé d’apprentissage

- On a vu comment **structurer un projet Python** avec modules, classes, séparation claire.  
- On a appris les bases de la **crypto moderne** : sel, KDF, vérificateur, coffre chiffré.  
- On a intégré tout ça dans une **GUI Tkinter** ergonomique, avec interactions (boutons, double-clic, status bar).  
- On a ajouté du **confort utilisateur** (feedback, effacement auto, i18n, confirmations).  
- Le projet est maintenant un **gestionnaire de mots de passe sécurisé et utilisable**.  
