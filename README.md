Task list :

* Faire en sorte qu'on puisse afficher et masquer les mdp sur l'interface graphique > KeyPass --fait--
* Deux langues à coder, anglais et français -- en cours-- 
* Appli à coder pour pc et smartphone, synchro à faire
* Bouton copier coller sur username et mdp --fait pour mdp--
* Bouton pour afficher/masquer le mot de passe --fait--
* Faire un all in one pour utilisateur (.exe)
* Faire une interface web (hmtl, css, js, sql)
* Intégration SQL pour la BDD de mot de passe
* Axer la programmation sur la sécurité -- fait--
* Ergonomie visuelle

Redimensionnement adaptatif
* Actuellement, la fenêtre principale est fixe. On peut la rendre redimensionnable, et le Treeview s’adapte automatiquement (colonnes qui suivent).

Colonnes triables
* Un clic sur l’en-tête trie par nom/website/username.

Icônes
* Ajouter une icône de fenêtre (favicon .ico ou .png).
* Thème clair/sombre (Tkinter supporte les styles via ttk.Style, on peut gérer un switch simple).

 Expérience utilisateur
* Double-clic sur une entrée = afficher ou copier automatiquement le mot de passe (au choix). --fait--
* Raccourcis clavier (Ctrl+N = New entry, Ctrl+C = Copy, Suppr = Delete).
* Confirmation avant suppression avec un message clair “Delete entry X ?”. --fait--

Navigation & organisation

* Barre de recherche en haut → filtre direct sur le Treeview.
* Tags (champ optionnel dans Entry) → pouvoir filtrer par “perso”, “pro”, etc.

Menu contextuel (clic droit) sur une ligne (Copy / Show / Edit / Delete rapides).

Paramètres

* Choix du délai par défaut (clipboard clear, show timeout) via une fenêtre “Preferences”.
* Choix de la langue (EN/FR) via un menu déroulant plutôt que dans le code.
* Option “Always hide passwords” (forcer les mots de passe à être masqués au lancement).
