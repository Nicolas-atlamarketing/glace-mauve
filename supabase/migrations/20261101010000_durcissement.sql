-- Durcissement (Security Advisor) : les fonctions d'aide des règles RLS quittent le schéma
-- exposé par l'API (public) pour le schéma private. Le schéma private devient utilisable
-- par authenticated, mais ses tables restent sans aucun droit (codes de secours illisibles).

grant usage on schema private to authenticated;

create or replace function private.is_aal2() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
$$;

create or replace function private.member_row() returns public.league_members
language sql stable security definer set search_path = '' as $$
  select m.* from public.league_members m
  join auth.users u on lower(u.email) = m.email
  where u.id = auth.uid() and u.email_confirmed_at is not null
$$;

create or replace function private.is_member() returns boolean
language sql stable security definer set search_path = '' as $$
  select (private.member_row()).email is not null
$$;

create or replace function private.can_play() returns boolean
language sql stable set search_path = '' as $$
  select private.is_aal2() and private.is_member()
$$;

create or replace function private.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select private.can_play() and coalesce((private.member_row()).is_admin, false)
$$;

revoke all on function private.is_aal2(), private.member_row(), private.is_member(),
  private.can_play(), private.is_admin() from public, anon;
grant execute on function private.is_aal2(), private.member_row(), private.is_member(),
  private.can_play(), private.is_admin() to authenticated;

alter policy members_select on public.league_members using (private.is_admin() or email = (private.member_row()).email);
alter policy members_insert on public.league_members with check (private.is_admin() and is_admin = false and invited_by = auth.uid());
alter policy members_delete on public.league_members using (private.is_admin() and is_admin = false);

alter policy profiles_select on public.profiles using (private.can_play());
alter policy profiles_insert on public.profiles with check (private.can_play() and id = auth.uid());
alter policy profiles_update on public.profiles using (private.can_play() and id = auth.uid()) with check (id = auth.uid());

alter policy games_select on public.games using (private.can_play());
alter policy games_insert on public.games with check (private.can_play() and player_id = auth.uid());
alter policy games_update on public.games using (private.can_play() and player_id = auth.uid()) with check (player_id = auth.uid());
alter policy games_delete on public.games using (private.can_play() and player_id = auth.uid());

-- RPC restant publiques : elles n'agissent que sur le compte de l'appelant.
create or replace function public.generate_recovery_codes() returns text[]
language plpgsql security definer set search_path = '' as $$
declare
  codes text[] := '{}';
  raw text;
begin
  if auth.uid() is null or not private.is_aal2() then
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
  select case when private.is_aal2()
    then (select count(*)::int from private.recovery_codes where user_id = auth.uid() and used_at is null)
    else null end
$$;

create or replace function public.whoami() returns json
language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'member', private.is_member(),
    'admin',  coalesce((private.member_row()).is_admin, false),
    'aal2',   private.is_aal2()
  )
$$;

drop function public.is_admin(), public.can_play(), public.is_member(), public.member_row(), public.is_aal2();
