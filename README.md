# Ghost Data Still Exists — auditeur de suppression

Ce dépôt contient une solution Python déterministe de base pour le défi
HackerRank Orchestrate « Ghost Data Still Exists ». Le jeu de données du défi
et les prédictions générées ne sont volontairement pas inclus.

## Récupérer le jeu de données participant

Récupérez les fichiers accessibles aux participants depuis le dépôt officiel
du défi :

<https://github.com/interviewstreet/hackerrank-orchestrate-october26>

Placez le dossier `dataset/` à la racine de ce dépôt, à côté de `code/` :

```text
ghost-data-deletion-auditor/
├── dataset/
└── code/
```

Ne copiez pas de données réservées aux organisateurs, de réponses privées,
d’identifiants de connexion ni aucun autre contenu soumis à restriction.

## Exécuter le programme

Python 3.10 ou une version ultérieure est nécessaire :

```bash
python3 code/main.py
python3 code/evaluation/main.py
```

Le programme n’utilise que la bibliothèque standard de Python et écrit
`output.csv` à la racine du dépôt. Si la commande locale `pdftotext` est
disponible, elle sert à extraire le texte des PDF. Tesseract est facultatif ;
en son absence, les preuves contenues dans les images PNG sont ignorées et un
avertissement est affiché.

## Approche

Le pipeline reconstitue les identifiants actuels et historiques, suit les
liens d’identité présents dans l’activité système, analyse les preuves JSON,
texte, PDF et SQL compatibles avec SQLite, puis filtre les observations selon
la date `audit_at` de chaque demande. Il applique les règles de suppression
aux preuves regroupées par système et ressource, puis produit les constats,
les actions correctives et les vérifications dans l’ordre requis. Une demande
qui n’autorise pas la suppression reçoit le statut `NOT_APPLICABLE` et une
liste d’étapes vide.

Le script d’évaluation vérifie le schéma et la structure du résultat, compare
les prédictions aux exemples publics fournis aux participants et exécute des
tests synthétiques. Les exemples publics servent uniquement à l’évaluation ;
ils ne sont pas utilisés pour produire les prédictions.

## Évaluation et limites

Sur les 32 exemples publics, l’exactitude mesurée des statuts est de **65,6 %**
et l’exactitude des cas entièrement corrects — statut et séquence d’étapes — est
de **9,4 %**. Ces résultats montrent qu’il s’agit d’une base expérimentale,
et non d’un auditeur de suppression fiable pour un usage en production. Parmi
les limites connues : la classification heuristique des ressources et les
captures d’écran ignorées lorsque Tesseract n’est pas installé. Consultez le
[rapport d’évaluation](code/evaluation/evaluation_report.md) pour les détails
et le [rapport d’utilisation](code/evaluation/usage_report.md) pour les
informations d’exécution.

À l’exécution, le programme ne fait appel à aucune API de modèle.
