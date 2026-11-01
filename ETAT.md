# ETAT — Hockey Stats (app stats hockey ; dépôt/URL « glace-mauve »)

## Objectif
App web FR de stats hockey (buts, passes, +/−, points auto) pour Nicolas + un ami, extensible à d'autres amis.
Comptes perso, 2FA obligatoire, données partagées synchronisées. Design mauve/blanc/cyan glacé, 3D. Gratuit uniquement.

## Architecture (décidée le 2026-11-01)
- Front statique `web/` → GitHub Pages (dépôt public `Nicolas-atlamarketing/glace-mauve`, branche `gh-pages`).
- Back : Supabase **organisation gratuite perso** (l'org Pro « Technologie Van Guard » facture 10 $/mois par projet → interdit).
- Pourquoi pas Artifact claude.ai : impossible d'y imposer une vraie 2FA. Vercel : exclu (compte bloqué).

## Fichiers clés
- `supabase/migrations/20261101000000_glace_mauve.sql` — schéma, RLS (membre + aal2), points calculés, codes de secours, admin seed.
- `supabase/tests/securite_rls.sql` — test serveur multi-identités, tout est annulé à la fin (RAISE).
- `web/index.html` — écrans (auth, 2FA, codes, profil, app) + CSP.
- `web/app.js` — logique (supabase-js 2.45.4 via CDN + SRI), temps réel, saisie.
- `web/scene.js` — scène three.js r128 (niveaux full/low/still/off).
- `web/config.js` — URL + clé publishable (publiques). Jamais la clé service_role.
- `SECURITE.md` — revue de sécurité, tests faits, limites.

## Décisions
- Accès = courriel confirmé présent dans `league_members` ET session aal2 (vérifié par RLS, pas par le client).
- Chacun n'écrit que ses propres matchs/profil ; l'admin ne peut pas modifier les stats d'un autre (anti-usurpation).
- Points = colonne générée `goals + assists` ; classement = vue `leaderboard` (security_invoker).
- Codes de secours : 10, hachés bcrypt dans le schéma `private`, 5 essais / 15 min ; un code valide supprime les facteurs 2FA → réenrôlement.
- Admin : compte perso de Nicolas (courriel dans league_members uniquement). Dépôt public → aucun courriel réel dans les fichiers ni les commits (auteur = adresse noreply GitHub).

## À faire / En cours / Fait
- Fait (2026-11-01) : logo « HS » sur palet 3D (web/logo.svg) : en-tête, favicon, apple-touch-icon.png 180 px (rendu par qlmanage + sips depuis une copie sans coins arrondis).
- Fait (2026-11-01) : case « Se souvenir de moi » (cochée : session localStorage + courriel pré-rempli ; décochée : sessionStorage, rien retenu). Adaptateur `authStorage` dans app.js.
- Fait (2026-11-01) : Nicolas inscrit, 2FA active, app confirmée fonctionnelle par lui. Historique Git réécrit (courriels retirés).
- Cette semaine : Nicolas saisit ses matchs manuellement dans l'app.
- Fait : durcissement sécurité (fonctions RLS dans private, mdp 10+ lettres/chiffres, test 32/32 après). Voir SECURITE.md.
- Fait : dépôt GitHub supprimé puis recréé (même nom/URL) avec historique propre ; anciens commits introuvables (404) ; copie locale purgée.
- Fait : ami invité (2e membre, non admin ; courriel dans la table league_members, jamais dans ce dépôt public) ; lien envoyé par iMessage.
- Règle : aucun courriel/téléphone d'ami dans le dépôt (public).
- À faire : Michael s'inscrit avec ce courriel exact, active sa 2FA ; tester à deux (sync + isolation).
- Fait : org gratuite « Hockey perso » + projet `dumelejmmfdmjsayewhg` (us-east-1), migration appliquée,
  test sécurité 32/32 OK (annulé), Site URL Auth = GitHub Pages, config.js branché, site publié.
- Note : le connecteur Supabase MCP ne voit que l'org Pro ; SQL appliqué via l'éditeur du tableau de bord
  (`create extension http` → `execute http_get(raw GitHub @commit)` → `drop extension http`).

## Liens
- App : https://nicolas-atlamarketing.github.io/glace-mauve/
- Dépôt : https://github.com/Nicolas-atlamarketing/glace-mauve
- Supabase : https://supabase.com/dashboard/project/dumelejmmfdmjsayewhg

## Commandes
- Aperçu local : `python3 -m http.server 5178 --directory web` (ou preview « glace-mauve »).
- Vérif syntaxe : `node --check web/app.js web/scene.js`.
- Déployer : `C=$(git commit-tree $(git rev-parse HEAD:web) -p origin/gh-pages -m deploy) && git push origin $C:refs/heads/gh-pages` (après `git fetch origin gh-pages`)

## Pièges
- CSP stricte : pas de script/style inline, pas d'attribut style= dans les gabarits (utiliser style.setProperty).
- Confirmation courriel : Site URL Supabase par défaut = localhost → à régler dans le tableau de bord.
- Courriels Supabase gratuits : 2/heure max (inscriptions + réinitialisations). Lien de réinitialisation déclenché hors appareil (tableau de bord / API) : géré par app.js (jetons du fragment → setSession).
