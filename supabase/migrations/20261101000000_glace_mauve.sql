-- Glace Mauve : stats de hockey entre amis.
-- Sécurité : tout accès aux données exige (1) un compte dont le courriel confirmé
-- figure dans la liste des membres et (2) une session 2FA (aal2).
-- Chaque joueur ne peut écrire que ses propres données ; les points sont calculés par la base.

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------- membres
create table public.league_members (
  email      text primary key check (email = lower(btrim(email)) and char_length(email) between 3 and 254 and email like '%_@_%'),
  is_admin   boolean not null default false,
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
alter table public.league_members enable row level security;

create or replace function public.is_aal2() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
$$;

-- Le courriel vient de auth.users (confirmé), jamais d'une valeur fournie par le client.
create or replace function public.member_row() returns public.league_members
language sql stable security definer set search_path = '' as $$
  select m.* from public.league_members m
  join auth.users u on lower(u.email) = m.email
  where u.id = auth.uid() and u.email_confirmed_at is not null
$$;

create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select (public.member_row()).email is not null
$$;

create or replace function public.can_play() returns boolean
language sql stable set search_path = '' as $$
  select public.is_aal2() and public.is_member()
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select public.can_play() and coalesce((public.member_row()).is_admin, false)
$$;

create policy members_select on public.league_members for select to authenticated
  using (public.is_admin() or email = (public.member_row()).email);
create policy members_insert on public.league_members for insert to authenticated
  with check (public.is_admin() and is_admin = false and invited_by = auth.uid());
create policy members_delete on public.league_members for delete to authenticated
  using (public.is_admin() and is_admin = false);

-- ---------------------------------------------------------------- joueurs
create table public.profiles (
  id           uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  display_name text not null check (char_length(btrim(display_name)) between 1 and 24 and display_name !~ '[[:cntrl:]]'),
  jersey       smallint check (jersey between 0 and 99),
  position     text not null default 'Attaquant' check (position in ('Attaquant', 'Défenseur', 'Polyvalent', 'Gardien')),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
alter table public.profiles enable row level security;

create policy profiles_select on public.profiles for select to authenticated using (public.can_play());
create policy profiles_insert on public.profiles for insert to authenticated
  with check (public.can_play() and id = auth.uid());
create policy profiles_update on public.profiles for update to authenticated
  using (public.can_play() and id = auth.uid()) with check (id = auth.uid());

-- ---------------------------------------------------------------- matchs
create table public.games (
  id         uuid primary key default gen_random_uuid(),
  player_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  played_on  date not null check (played_on >= date '2000-01-01'),
  opponent   text check (opponent is null or (char_length(opponent) <= 40 and opponent !~ '[[:cntrl:]]')),
  goals      smallint not null default 0 check (goals between 0 and 20),
  assists    smallint not null default 0 check (assists between 0 and 20),
  plus_minus smallint not null default 0 check (plus_minus between -15 and 15),
  points     smallint generated always as (goals + assists) stored,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index games_player_date on public.games (player_id, played_on desc);
alter table public.games enable row level security;

create policy games_select on public.games for select to authenticated using (public.can_play());
create policy games_insert on public.games for insert to authenticated
  with check (public.can_play() and player_id = auth.uid());
create policy games_update on public.games for update to authenticated
  using (public.can_play() and player_id = auth.uid()) with check (player_id = auth.uid());
create policy games_delete on public.games for delete to authenticated
  using (public.can_play() and player_id = auth.uid());

-- Horodatage imposé par le serveur, date future refusée, limite anti-abus.
create or replace function public.games_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.played_on > current_date + 1 then
    raise exception 'Date de match dans le futur' using errcode = '22023';
  end if;
  if tg_op = 'INSERT' then
    new.created_at := now();
    if (select count(*) from public.games g
        where g.player_id = new.player_id and g.created_at > now() - interval '1 hour') >= 30 then
      raise exception 'Trop de saisies en une heure, réessaie plus tard' using errcode = '54000';
    end if;
  else
    new.created_at := old.created_at;
    new.player_id := old.player_id;
  end if;
  new.updated_at := now();
  return new;
end $$;
create trigger games_guard before insert or update on public.games
  for each row execute function public.games_guard();

create or replace function public.profiles_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.display_name := btrim(new.display_name);
  if tg_op = 'INSERT' then new.created_at := now(); else new.created_at := old.created_at; new.id := old.id; end if;
  new.updated_at := now();
  return new;
end $$;
create trigger profiles_guard before insert or update on public.profiles
  for each row execute function public.profiles_guard();

-- ---------------------------------------------------------------- classement (calcul serveur)
create view public.leaderboard with (security_invoker = true) as
select p.id, p.display_name, p.jersey, p.position,
       count(g.id)::int                     as games_played,
       coalesce(sum(g.goals), 0)::int       as goals,
       coalesce(sum(g.assists), 0)::int     as assists,
       coalesce(sum(g.points), 0)::int      as points,
       coalesce(sum(g.plus_minus), 0)::int  as plus_minus
from public.profiles p
left join public.games g on g.player_id = p.id
group by p.id;

-- ---------------------------------------------------------------- 2FA : codes de secours
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table private.recovery_codes (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  code_hash  text not null,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);
create table private.recovery_attempts (
  user_id      uuid not null references auth.users(id) on delete cascade,
  attempted_at timestamptz not null default now()
);
create index recovery_attempts_user on private.recovery_attempts (user_id, attempted_at desc);

-- Génère 10 nouveaux codes (remplace les anciens). Exige une session 2FA.
create or replace function public.generate_recovery_codes() returns text[]
language plpgsql security definer set search_path = '' as $$
declare
  codes text[] := '{}';
  raw text;
begin
  if auth.uid() is null or not public.is_aal2() then
    raise exception 'Session 2FA requise' using errcode = '42501';
  end if;
  delete from private.recovery_codes where user_id = auth.uid();
  for i in 1..10 loop
    raw := upper(encode(extensions.gen_random_bytes(5), 'hex'));
    raw := substr(raw, 1, 5) || '-' || substr(raw, 6, 5);
    insert into private.recovery_codes (user_id, code_hash)
      values (auth.uid(), extensions.crypt(raw, extensions.gen_salt('bf', 8)));
    codes := codes || raw;
  end loop;
  return codes;
end $$;

create or replace function public.recovery_codes_left() returns int
language sql stable security definer set search_path = '' as $$
  select case when public.is_aal2()
    then (select count(*)::int from private.recovery_codes where user_id = auth.uid() and used_at is null)
    else null end
$$;

-- Téléphone perdu : un code de secours valide supprime les facteurs 2FA du compte,
-- qui doit ensuite en enregistrer un nouveau. 5 essais par 15 minutes.
create or replace function public.redeem_recovery_code(p_code text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := auth.uid();
  norm text;
  hit bigint;
begin
  if uid is null then
    raise exception 'Connexion requise' using errcode = '42501';
  end if;
  if (select count(*) from private.recovery_attempts
      where user_id = uid and attempted_at > now() - interval '15 minutes') >= 5 then
    raise exception 'Trop d''essais, réessaie dans 15 minutes' using errcode = '54000';
  end if;
  insert into private.recovery_attempts (user_id) values (uid);

  norm := upper(regexp_replace(coalesce(p_code, ''), '[^0-9A-Fa-f]', '', 'g'));
  if char_length(norm) <> 10 then return false; end if;
  norm := substr(norm, 1, 5) || '-' || substr(norm, 6, 5);

  select id into hit from private.recovery_codes
   where user_id = uid and used_at is null and code_hash = extensions.crypt(norm, code_hash)
   limit 1;
  if hit is null then return false; end if;

  update private.recovery_codes set used_at = now() where id = hit;
  delete from auth.mfa_factors where user_id = uid;
  return true;
end $$;

-- État du compte pour l'interface (aucune donnée d'autrui).
create or replace function public.whoami() returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'member', public.is_member(),
    'admin',  coalesce((public.member_row()).is_admin, false),
    'aal2',   public.is_aal2()
  )
$$;

-- ---------------------------------------------------------------- droits
revoke all on public.league_members, public.profiles, public.games, public.leaderboard from anon;
grant select, insert, delete on public.league_members to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.games to authenticated;
grant select on public.leaderboard to authenticated;
revoke all on function public.generate_recovery_codes(), public.recovery_codes_left(),
  public.redeem_recovery_code(text), public.whoami(), public.member_row(),
  public.is_member(), public.is_admin(), public.can_play(), public.is_aal2() from public, anon;
grant execute on function public.generate_recovery_codes(), public.recovery_codes_left(),
  public.redeem_recovery_code(text), public.whoami(), public.member_row(),
  public.is_member(), public.is_admin(), public.can_play(), public.is_aal2() to authenticated;
-- id, player_id et created_at sont figés par les déclencheurs *_guard (un revoke de colonne
-- n'aurait aucun effet face au droit UPDATE accordé sur la table).

alter publication supabase_realtime add table public.games, public.profiles;

-- Premier administrateur : à insérer à la main dans l'éditeur SQL (aucun courriel réel dans ce dépôt public) :
--   insert into public.league_members (email, is_admin) values ('<courriel-admin>', true);
