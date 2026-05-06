# Portfolio — Antoine Bonnet

## Fichiers

| Fichier | Description |
|---|---|
| `index.html` | Page d'accueil — hero + slider projets + CTA |
| `about.html` | Page À propos / CV détaillé |
| `cv.html` | CV format A4 imprimable + bouton PDF |
| `project01.html` | Page projet — Gestion des congés |

## À faire avant de mettre en ligne

### Images (dossier `/images/`)
Les placeholders dans `project01.html` attendent ces fichiers :
- `images/app_conges_home.png` — capture page d'accueil de l'app
- `images/app_conges_cp.png` — capture formulaire congés
- `images/app_conges_admin.png` — capture interface admin

Pour activer une image, remplacer le bloc `<div style="height:...">...</div>` par :
```html
<img src="images/nom_image.png" alt="Description">
```

### Liens à vérifier
- LinkedIn dans `cv.html` et `about.html` → vérifier l'URL exacte
- GitHub dans tous les fichiers → `https://github.com/BonnetAntoine`
- Email → `antoinebonnet54@gmail.com`

### Déploiement GitHub Pages
Pousser tous les fichiers à la racine du repo `BonnetAntoine.github.io`.
La page sera accessible sur `https://bonnetantoine.github.io`.

## Dupliquer une page projet

Pour créer `project3.html` (Automatisation des contrats) :
1. Copier `project01.html` → `project3.html`
2. Changer : titre hero, numéro de fond (`01`→`02`), méta, étapes timeline, fonctionnalités, métriques, stack
3. Mettre à jour la navigation bas de page (liens précédent/suivant)
