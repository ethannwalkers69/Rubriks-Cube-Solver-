-- Patakbuhin sa Neon SQL Editor (gamit ang owner role). Palitan ang dalawang CHANGE_ME.
create extension if not exists pgcrypto;

create table if not exists visitors (
  id         bigserial primary key,
  username   text not null,
  created_at timestamptz not null default now()
);

-- Admin password (naka-hash sa loob ng database, hindi nasa HTML)
create table if not exists admin_config (
  id      int primary key default 1 check (id = 1),
  pw_hash text not null
);
insert into admin_config (pw_hash) values (crypt('CHANGE_ME_ADMIN_PASSWORD', gen_salt('bf')))
on conflict (id) do nothing;

-- Mag-save ng username (ito lang ang puwedeng gawin ng public page)
create or replace function log_visit(p_username text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if length(trim(p_username)) < 2 then return; end if;
  insert into visitors (username) values (left(trim(p_username), 24));
end $$;

-- Listahan ng users — kailangan ang tamang admin password
create or replace function admin_list(p_pw text)
returns table (id bigint, username text, created_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from admin_config where pw_hash = crypt(p_pw, pw_hash)) then
    raise exception 'wrong password';
  end if;
  return query select v.id, v.username, v.created_at from visitors v order by v.created_at desc limit 500;
end $$;

-- Restricted role para sa website: walang direct access sa tables, dalawang function lang.
create role app_public login password 'CHANGE_ME_ROLE_PASSWORD';
grant usage on schema public to app_public;
revoke all on function log_visit(text), admin_list(text) from public;
grant execute on function log_visit(text), admin_list(text) to app_public;

-- Para palitan ang admin password sa hinaharap:
-- update admin_config set pw_hash = crypt('bagong_password', gen_salt('bf'));
