# Sécurité — Glace Mauve

Revue défensive de notre propre application (2026-11-01). Aucune garantie de sécurité absolue.

## Architecture vérifiée
- Front statique sur GitHub Pages (HTTPS imposé) ; données et comptes sur Supabase (org gratuite « Hockey perso », projet `dumelejmmfdmjsayewhg`).
- Toute autorisation est appliquée **par la base** (Row Level Security), jamais par l'interface.
- Accès aux données = courriel **confirmé** inscrit dans `league_members` **et** session 2FA `aal2`.
- Pourquoi pas un Artifact claude.ai : la 2FA n'y est pas imposable par l'application (connexion gérée par claude.ai). Compromis refusé.

## Mesures en place
| Sujet | Mesure |
|---|---|
| Authentification | Courriel + mot de passe (10 car. min. côté client), confirmation du courriel obligatoire |
| 2FA | TOTP obligatoire : sans `aal2`, la base ne renvoie aucune donnée et refuse toute écriture |
| Codes de secours | 10 codes uniques, hachés bcrypt dans un schéma `private` non exposé, 5 essais / 15 min ; un code valide réinitialise la 2FA, qui doit être reconfigurée immédiatement |
| Isolation | Chacun n'écrit que son profil et ses matchs (`auth.uid()`), y compris l'admin : personne ne peut usurper un joueur |
| Invitations | Seul l'admin 2FA peut inviter ; impossible de créer un autre admin depuis l'app ; un inscrit non invité ne voit rien |
| Calculs | Points = colonne générée `buts + passes` ; classement = vue serveur ; le client ne peut pas écrire les points |
| Validation | Contraintes SQL (buts/passes 0-20, +/− −15..15, textes bornés sans caractères de contrôle, date non future) + validation client |
| Anti-abus | 30 saisies de match / heure / joueur (déclencheur) ; limites natives Supabase sur connexion, inscription, 2FA |
| XSS | Affichage via échappement/`textContent` ; CSP stricte sans script ni style en ligne ; bibliothèques CDN figées avec SRI |
| Secrets | Le client ne contient que l'URL et la clé *publishable* (publique par conception) ; aucune clé secrète dans le dépôt |
| Divers | `referrer: no-referrer`, anti-iframe en JS, export CSV protégé contre l'injection de formules, flux PKCE |

## Tests réellement effectués
1. **Test serveur multi-identités** (`supabase/tests/securite_rls.sql`), exécuté sur la vraie base puis annulé : **32/32 OK**, 0 faille.
   Identités simulées par jetons : admin A, ami B, intrus C non invité, B sans 2FA, anonyme.
   Couvre : lecture partagée, saisie/modification/suppression au nom d'autrui, renommage d'autrui, transfert de match, points falsifiés, bornes, date future, invitations, création d'admin, accès sans 2FA, accès non-invité, accès anonyme, schéma `private`, limite de saisies, codes de secours (faux, vrai, réutilisé, limite d'essais, réinitialisation du facteur).
2. **Test réseau réel** depuis le site publié (HTTPS) : appels anonymes à `games` et `whoami` → **401 refusés**.
3. Vérification post-test : seule la ligne admin subsiste, l'extension `http` utilisée pour le chargement a été retirée.
4. Aperçu local et site publié : aucune erreur console, CSP compatible.

## Limites (honnêtes)
- **Pas encore testé de bout en bout avec deux vrais comptes humains** (inscription → courriel → QR → code). Je ne peux pas créer de vrais comptes ni saisir de mots de passe : à faire par Nicolas et l'ami. Les identités du test 1 sont simulées au niveau de la base (même mécanisme que les jetons réels, mais pas la couche Auth).
- Protection contre les mots de passe divulgués : fonction payante de Supabase, non activée. Longueur minimale serveur = défaut Supabase (6) ; 10 imposé seulement côté client.
- GitHub Pages ne permet pas d'en-têtes HTTP personnalisés : CSP via `<meta>`, anti-iframe en JS (pas `frame-ancestors`).
- Session stockée dans le navigateur (localStorage) : un XSS la volerait ; atténué par CSP + échappement.
- Le propriétaire du projet Supabase (Nicolas) garde un accès total via le tableau de bord : c'est aussi la voie de récupération ultime si tous les codes de secours sont perdus (Authentication → Users → supprimer le facteur MFA).
- Projet gratuit : mis en pause après ~7 jours sans activité (réactivation gratuite dans le tableau de bord). Envoi de courriels Supabase limité (quelques/heure).
- Dépôt public : le code est lisible (aucun secret dedans) ; la sécurité ne repose pas sur son secret.
- Historique Git réécrit (courriels retirés des fichiers et des auteurs), mais GitHub garde les anciens commits accessibles par leur identifiant tant que le dépôt n'est pas supprimé et recréé.

## Passe de durcissement (2026-11-01, après mise en service)
- Security Advisor Supabase : 0 erreur. Les fonctions d'aide RLS (`is_member`, `is_admin`, `member_row`, `can_play`, `is_aal2`) sont passées dans le schéma `private` → plus appelables par l'API (vérifié : 404). Restent publiques, par conception, 4 RPC qui n'agissent que sur le compte appelant (`whoami`, `generate_recovery_codes`, `recovery_codes_left`, `redeem_recovery_code`).
- Test multi-identités relancé après durcissement : **32/32 OK**.
- Réglages Auth : mot de passe 10 caractères min. + lettres et chiffres (serveur et client), changement de mot de passe sécurisé activé, changement de courriel sécurisé actif, confirmation du courriel obligatoire.
- État réel vérifié : 1 compte (admin), courriel confirmé, 2FA vérifiée ; 2 membres invités ; aucun compte non invité.
- Non activable gratuitement : protection contre les mots de passe divulgués (forfait Pro).
