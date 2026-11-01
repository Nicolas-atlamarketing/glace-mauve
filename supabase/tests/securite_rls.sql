-- Test de sécurité à identités multiples, exécuté côté serveur puis ANNULÉ (aucune trace).
-- A = admin de ligue, B = ami membre, C = compte inscrit mais non invité.
-- Chaque ligne du rapport : OK (comportement attendu) ou KO (faille).
do $$
declare
  a uuid := gen_random_uuid(); b uuid := gen_random_uuid(); c uuid := gen_random_uuid();
  out text := ''; n int; gid uuid; bgid uuid; codes text[]; res boolean; pts int;
begin
  -- Fixtures (supprimées par l'annulation finale).
  insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, created_at, updated_at)
  values (a, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'a@test.invalid', now(), now(), now()),
         (b, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'b@test.invalid', now(), now(), now()),
         (c, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'c@test.invalid', now(), now(), now());
  insert into public.league_members (email, is_admin) values ('a@test.invalid', true), ('b@test.invalid', false);
  insert into auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret)
  values (gen_random_uuid(), a, 'test', 'totp', 'verified', now(), now(), 'X');

  -- ---------- anonyme
  set local role anon;
  begin perform 1 from public.games; out := out || E'\nKO anon lit games'; exception when others then out := out || E'\nOK anon refusé sur games (' || sqlstate || ')'; end;
  begin perform public.whoami(); out := out || E'\nKO anon appelle whoami'; exception when others then out := out || E'\nOK anon refusé sur RPC (' || sqlstate || ')'; end;
  reset role;

  -- ---------- A (aal2) crée son profil et un match
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role', 'authenticated', 'aal', 'aal2')::text, true);
  set local role authenticated;
  insert into public.profiles (display_name, jersey) values ('Alpha', 9);
  insert into public.games (played_on, goals, assists, plus_minus, created_at) values (current_date, 2, 1, 1, '2001-01-01') returning id, points into gid, pts;
  out := out || case when pts = 3 then E'\nOK points calculés par le serveur (2+1=3)' else E'\nKO points = ' || pts end;
  select count(*) into n from public.games where id = gid and created_at > now() - interval '1 minute';
  out := out || case when n = 1 then E'\nOK created_at imposé par le serveur' else E'\nKO created_at falsifiable' end;
  begin insert into public.games (played_on, goals, assists, points) values (current_date, 0, 0, 50); out := out || E'\nKO points écrits par le client';
  exception when others then out := out || E'\nOK points non modifiables (' || sqlstate || ')'; end;
  begin insert into public.games (played_on, goals) values (current_date, 99); out := out || E'\nKO 99 buts acceptés';
  exception when others then out := out || E'\nOK bornes de validation (' || sqlstate || ')'; end;
  begin insert into public.games (played_on) values (current_date + 10); out := out || E'\nKO date future acceptée';
  exception when others then out := out || E'\nOK date future refusée (' || sqlstate || ')'; end;
  begin insert into public.profiles (id, display_name) values (b, 'Usurpé'); out := out || E'\nKO A crée le profil de B';
  exception when others then out := out || E'\nOK A ne peut pas créer le profil de B (' || sqlstate || ')'; end;
  reset role;

  -- ---------- B (aal2) : isolation par rapport à A
  perform set_config('request.jwt.claims', json_build_object('sub', b, 'role', 'authenticated', 'aal', 'aal2')::text, true);
  set local role authenticated;
  insert into public.profiles (display_name) values ('Bravo');
  select count(*) into n from public.games where id = gid;
  out := out || case when n = 1 then E'\nOK B (membre 2FA) voit les matchs partagés' else E'\nKO B ne voit pas les matchs' end;
  begin insert into public.games (player_id, played_on, goals) values (a, current_date, 5); out := out || E'\nKO B saisit un match au nom de A';
  exception when others then out := out || E'\nOK B ne peut pas saisir au nom de A (' || sqlstate || ')'; end;
  update public.games set goals = 20 where id = gid; get diagnostics n = row_count;
  out := out || case when n = 0 then E'\nOK B ne peut pas modifier les stats de A' else E'\nKO B a modifié un match de A' end;
  delete from public.games where id = gid; get diagnostics n = row_count;
  out := out || case when n = 0 then E'\nOK B ne peut pas supprimer un match de A' else E'\nKO B a supprimé un match de A' end;
  update public.profiles set display_name = 'Pirate' where id = a; get diagnostics n = row_count;
  out := out || case when n = 0 then E'\nOK B ne peut pas renommer A' else E'\nKO B a renommé A' end;
  insert into public.games (played_on, goals) values (current_date, 1) returning id into bgid;
  begin update public.games set player_id = a where id = bgid;
    select count(*) into n from public.games where id = bgid and player_id = b;
    out := out || case when n = 1 then E'\nOK transfert de match vers A neutralisé' else E'\nKO match transféré à A' end;
  exception when others then out := out || E'\nOK transfert de match vers A refusé (' || sqlstate || ')'; end;
  select points into pts from public.leaderboard where id = a;
  out := out || case when pts = 3 then E'\nOK classement serveur intact (A = 3 PTS)' else E'\nKO classement A = ' || coalesce(pts, -1) end;
  begin insert into public.league_members (email) values ('x@test.invalid'); out := out || E'\nKO B (non admin) invite quelqu''un';
  exception when others then out := out || E'\nOK seul l''admin peut inviter (' || sqlstate || ')'; end;
  select count(*) into n from public.league_members;
  out := out || case when n = 1 then E'\nOK B ne voit que sa propre adhésion' else E'\nKO B voit ' || n || ' adhésions' end;
  begin perform 1 from private.recovery_codes; out := out || E'\nKO schéma private lisible';
  exception when others then out := out || E'\nOK codes de secours inaccessibles directement (' || sqlstate || ')'; end;
  -- limite anti-abus : 30 saisies par heure
  begin
    for i in 1..30 loop insert into public.games (played_on) values (current_date); end loop;
    out := out || E'\nKO 31 saisies en une heure acceptées';
  exception when others then out := out || E'\nOK limite de 30 saisies/heure (' || sqlstate || ')'; end;
  reset role;

  -- ---------- B sans 2FA (aal1) : aucun accès aux données
  perform set_config('request.jwt.claims', json_build_object('sub', b, 'role', 'authenticated', 'aal', 'aal1')::text, true);
  set local role authenticated;
  select count(*) into n from public.games;
  out := out || case when n = 0 then E'\nOK sans 2FA : aucune donnée lisible' else E'\nKO sans 2FA : ' || n || ' matchs lisibles' end;
  begin insert into public.games (played_on) values (current_date); out := out || E'\nKO sans 2FA : écriture acceptée';
  exception when others then out := out || E'\nOK sans 2FA : écriture refusée (' || sqlstate || ')'; end;
  begin perform public.generate_recovery_codes(); out := out || E'\nKO codes générés sans 2FA';
  exception when others then out := out || E'\nOK génération de codes exige la 2FA (' || sqlstate || ')'; end;
  reset role;

  -- ---------- C : inscrit, 2FA, mais non invité
  perform set_config('request.jwt.claims', json_build_object('sub', c, 'role', 'authenticated', 'aal', 'aal2')::text, true);
  set local role authenticated;
  select count(*) into n from public.profiles;
  out := out || case when n = 0 then E'\nOK non-invité : aucune donnée lisible' else E'\nKO non-invité lit ' || n || ' profils' end;
  begin insert into public.profiles (display_name) values ('Intrus'); out := out || E'\nKO non-invité crée un profil';
  exception when others then out := out || E'\nOK non-invité ne peut rien écrire (' || sqlstate || ')'; end;
  reset role;

  -- ---------- A : admin et codes de secours
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role', 'authenticated', 'aal', 'aal2')::text, true);
  set local role authenticated;
  begin insert into public.league_members (email, is_admin, invited_by) values ('z@test.invalid', true, a); out := out || E'\nKO admin crée un autre admin';
  exception when others then out := out || E'\nOK impossible de créer un admin depuis l''app (' || sqlstate || ')'; end;
  insert into public.league_members (email, invited_by) values ('d@test.invalid', a);
  out := out || E'\nOK admin 2FA invite un ami';
  codes := public.generate_recovery_codes();
  out := out || case when array_length(codes, 1) = 10 then E'\nOK 10 codes de secours générés' else E'\nKO codes générés : ' || coalesce(array_length(codes, 1), 0) end;
  reset role;

  -- A a perdu son téléphone : session aal1
  perform set_config('request.jwt.claims', json_build_object('sub', a, 'role', 'authenticated', 'aal', 'aal1')::text, true);
  set local role authenticated;
  res := public.redeem_recovery_code('00000-00000');
  out := out || case when not res then E'\nOK faux code de secours refusé' else E'\nKO faux code accepté' end;
  res := public.redeem_recovery_code(lower(replace(codes[1], '-', ' ')));
  out := out || case when res then E'\nOK vrai code accepté (saisie tolérante)' else E'\nKO vrai code refusé' end;
  res := public.redeem_recovery_code(codes[1]);
  out := out || case when not res then E'\nOK code déjà utilisé refusé' else E'\nKO code réutilisable' end;
  begin
    for i in 1..3 loop perform public.redeem_recovery_code('11111-11111'); end loop;
    out := out || E'\nKO pas de limite d''essais';
  exception when others then out := out || E'\nOK limite de 5 essais / 15 min (' || sqlstate || ')'; end;
  reset role;
  select count(*) into n from auth.mfa_factors where user_id = a;
  out := out || case when n = 0 then E'\nOK facteur 2FA de A réinitialisé par le code' else E'\nKO facteur 2FA toujours présent' end;

  raise exception 'RAPPORT (annulé, aucune donnée conservée) :%', out;
end $$;
