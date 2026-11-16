-- ═══════════════════════════════════════════════════════════════
-- Leki ratownika — konta bez adresu e-mail (nick + hasło)
-- Wklej całość w Supabase → SQL Editor → Run. Skrypt można uruchomić ponownie.
-- ═══════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

-- Konta: nick zapisany małymi literami jako klucz, hasło wyłącznie jako skrót bcrypt.
create table if not exists public.konta (
  nick              text primary key,
  nick_wyswietlany  text not null,
  haslo_hash        text not null,
  postep            jsonb not null default '{}'::jsonb,
  utworzono         timestamptz not null default now(),
  zmieniono         timestamptz not null default now()
);

-- Sesje: losowy token na każde urządzenie, na którym ktoś się zalogował.
create table if not exists public.sesje (
  token      uuid primary key default gen_random_uuid(),
  nick       text not null references public.konta(nick) on delete cascade,
  utworzono  timestamptz not null default now(),
  uzyto      timestamptz not null default now()
);
create index if not exists sesje_nick_idx on public.sesje(nick);

-- Tabele są niedostępne z zewnątrz; dostęp wyłącznie przez funkcje poniżej.
alter table public.konta enable row level security;
alter table public.sesje enable row level security;
revoke all on public.konta, public.sesje from anon, authenticated;

-- Scalanie postępu z dwóch urządzeń.
-- Format: { "best": { "nzk": {"v":100,"t":1731760000000} }, "umiem": { "Adrenalina": {"v":true,"t":...} }, "dop": {...} }
-- Dla "best" wygrywa wyższy wynik, dla pozostałych sekcji — nowsza zmiana.
create or replace function public._scal(a jsonb, b jsonb)
returns jsonb language sql immutable
set search_path = public
as $$
  select coalesce(jsonb_object_agg(s.sekcja, (
    select coalesce(jsonb_object_agg(z.k,
      case
        when z.xb is null then z.xa
        when z.xa is null then z.xb
        when s.sekcja = 'best' then
          case when coalesce((z.xa->>'v')::numeric, 0) >= coalesce((z.xb->>'v')::numeric, 0) then z.xa else z.xb end
        else
          case when coalesce((z.xa->>'t')::numeric, 0) >= coalesce((z.xb->>'t')::numeric, 0) then z.xa else z.xb end
      end), '{}'::jsonb)
    from (
      select kk.k, coalesce(a, '{}'::jsonb)->s.sekcja->kk.k as xa, coalesce(b, '{}'::jsonb)->s.sekcja->kk.k as xb
      from (
        select jsonb_object_keys(case when jsonb_typeof(coalesce(a, '{}'::jsonb)->s.sekcja) = 'object' then a->s.sekcja else '{}'::jsonb end) as k
        union
        select jsonb_object_keys(case when jsonb_typeof(coalesce(b, '{}'::jsonb)->s.sekcja) = 'object' then b->s.sekcja else '{}'::jsonb end)
      ) kk
    ) z
  )), '{}'::jsonb)
  from (
    select x as sekcja from unnest(array['best', 'umiem', 'dop']) as x
  ) s;
$$;

create or replace function public.rejestracja(p_nick text, p_haslo text)
returns json language plpgsql security definer
set search_path = public, extensions
as $$
declare
  n text := lower(trim(coalesce(p_nick, '')));
  t uuid;
begin
  if n !~ '^[a-z0-9ąćęłńóśźż._-]{3,20}$' then raise exception 'NICK_NIEPOPRAWNY'; end if;
  if char_length(coalesce(p_haslo, '')) < 6 then raise exception 'HASLO_ZA_KROTKIE'; end if;
  if octet_length(p_haslo) > 72 then raise exception 'HASLO_ZA_DLUGIE'; end if;
  begin
    insert into konta(nick, nick_wyswietlany, haslo_hash)
    values (n, trim(p_nick), crypt(p_haslo, gen_salt('bf', 10)));
  exception when unique_violation then
    raise exception 'NICK_ZAJETY';
  end;
  insert into sesje(nick) values (n) returning token into t;
  return json_build_object('token', t, 'nick', trim(p_nick), 'postep', '{}'::json);
end;
$$;

create or replace function public.logowanie(p_nick text, p_haslo text)
returns json language plpgsql security definer
set search_path = public, extensions
as $$
declare
  n text := lower(trim(coalesce(p_nick, '')));
  k konta%rowtype;
  t uuid;
begin
  select * into k from konta where nick = n;
  if not found or k.haslo_hash <> crypt(coalesce(p_haslo, ''), k.haslo_hash) then
    perform pg_sleep(0.4);                       -- spowalnia zgadywanie haseł
    raise exception 'BLEDNE_DANE';
  end if;
  delete from sesje where nick = n and uzyto < now() - interval '180 days';
  insert into sesje(nick) values (n) returning token into t;
  return json_build_object('token', t, 'nick', k.nick_wyswietlany, 'postep', k.postep);
end;
$$;

-- Wysyła postęp z urządzenia, scala go z zapisanym na koncie i zwraca wynik scalenia.
create or replace function public.synchronizuj(p_token uuid, p_postep jsonb)
returns json language plpgsql security definer
set search_path = public
as $$
declare
  n text;
  wynik jsonb;
begin
  update sesje set uzyto = now() where token = p_token returning nick into n;
  if n is null then raise exception 'SESJA_WYGASLA'; end if;
  if octet_length(coalesce(p_postep, '{}'::jsonb)::text) > 100000 then raise exception 'ZA_DUZO_DANYCH'; end if;
  update konta set postep = _scal(postep, coalesce(p_postep, '{}'::jsonb)), zmieniono = now()
  where nick = n returning postep into wynik;
  return json_build_object('postep', wynik);
end;
$$;

create or replace function public.wyloguj(p_token uuid)
returns void language sql security definer
set search_path = public
as $$ delete from sesje where token = p_token; $$;

create or replace function public.usun_konto(p_token uuid, p_haslo text)
returns void language plpgsql security definer
set search_path = public, extensions
as $$
declare
  n text;
  h text;
begin
  select s.nick, k.haslo_hash into n, h from sesje s join konta k on k.nick = s.nick where s.token = p_token;
  if n is null then raise exception 'SESJA_WYGASLA'; end if;
  if h <> crypt(coalesce(p_haslo, ''), h) then perform pg_sleep(0.4); raise exception 'BLEDNE_HASLO'; end if;
  delete from konta where nick = n;              -- sesje usuwają się kaskadowo
end;
$$;

-- Uprawnienia: strona (rola anon) może wywoływać tylko te pięć funkcji.
revoke all on function public._scal(jsonb, jsonb) from public, anon, authenticated;
revoke all on function public.rejestracja(text, text), public.logowanie(text, text), public.synchronizuj(uuid, jsonb),
              public.wyloguj(uuid), public.usun_konto(uuid, text) from public;
grant execute on function public.rejestracja(text, text), public.logowanie(text, text), public.synchronizuj(uuid, jsonb),
                          public.wyloguj(uuid), public.usun_konto(uuid, text) to anon, authenticated;
