-- AutoBOQ SUBAN CC · Supabase schema
-- Run in Supabase Dashboard → SQL Editor. Safe to re-run: after updating the app, run this whole file again to pick up new tables and rules.
-- Access model: only emails listed in public.members can read or write anything.

-- ---------- team members (allowlist) ----------
create table if not exists public.members (
  email      text primary key check (email = lower(email)),
  name       text not null default '',
  role       text not null default 'member' check (role in ('admin','member','viewer')),
  created_at timestamptz not null default now()
);

-- databases created before the 'viewer' role existed: widen the role check
alter table public.members drop constraint if exists members_role_check;
alter table public.members add constraint members_role_check check (role in ('admin','member','viewer'));

create or replace function public.is_member()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.members
    where email = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.members
    where email = lower(coalesce(auth.jwt() ->> 'email', '')) and role = 'admin'
  );
$$;

-- write access: admins and members. 'viewer' accounts can read everything but change nothing.
create or replace function public.can_write()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.members
    where email = lower(coalesce(auth.jwt() ->> 'email', '')) and role in ('admin','member')
  );
$$;

-- ---------- app data (JSON bodies mirror the app's in-memory shapes) ----------
create table if not exists public.projects (
  id         text primary key,
  info       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.boq (
  project_id text not null references public.projects(id) on delete cascade,
  code       text not null check (code in ('A','B','C','D','E','F','G','H')),
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (project_id, code)
);

create table if not exists public.drawings (
  id         text primary key,
  project_id text not null references public.projects(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists drawings_project_idx on public.drawings(project_id);

create table if not exists public.specs (
  id         text primary key,
  project_id text not null references public.projects(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists specs_project_idx on public.specs(project_id);

-- price library: one row per BOQ category, data = {items:[...]}
create table if not exists public.library (
  code       text primary key check (code in ('A','B','C','D','E','F','G','H')),
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

-- shared settings, e.g. key 'company' = quotation letterhead
create table if not exists public.settings (
  key        text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

-- quotation snapshots: one row per issued revision, data = {label, at, by, quoteNo, grand, info, cats}
create table if not exists public.revisions (
  id         text primary key,
  project_id text not null references public.projects(id) on delete cascade,
  data       jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists revisions_project_idx on public.revisions(project_id, created_at desc);

-- running document numbers (QT-2569-001, INV-2569-001), only reachable through next_doc_no()
create table if not exists public.counters (
  key   text primary key,
  value integer not null default 0
);

create or replace function public.next_doc_no(prefix text, yr integer)
returns text language plpgsql security definer set search_path = public as $$
declare n integer; k text;
begin
  if not public.can_write() then raise exception 'not allowed' using errcode = '42501'; end if;
  if upper(prefix) not in ('QT','INV') then raise exception 'unknown prefix'; end if;
  k := upper(prefix) || '-' || yr;
  insert into public.counters(key, value) values (k, 1)
    on conflict (key) do update set value = public.counters.value + 1
    returning value into n;
  return k || '-' || lpad(n::text, 3, '0');
end $$;
revoke all on function public.next_doc_no(text, integer) from public;
grant execute on function public.next_doc_no(text, integer) to authenticated;

-- merge a patch into projects.info atomically (two people editing different fields never overwrite each other)
create or replace function public.merge_project_info(pid text, patch jsonb)
returns void language sql security invoker set search_path = public as $$
  update public.projects set info = info || patch, updated_at = now() where id = pid;
$$;

-- keep updated_at fresh on every write
create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings'] loop
    execute format('drop trigger if exists touch_%1$s on public.%1$s', t);
    execute format('create trigger touch_%1$s before update on public.%1$s for each row execute function public.touch_updated_at()', t);
  end loop;
end $$;

-- ---------- row level security ----------
alter table public.members  enable row level security;
alter table public.projects enable row level security;
alter table public.boq      enable row level security;
alter table public.drawings enable row level security;
alter table public.specs    enable row level security;
alter table public.library  enable row level security;
alter table public.settings enable row level security;
alter table public.revisions enable row level security;
alter table public.counters enable row level security;

drop policy if exists "members read" on public.members;
create policy "members read" on public.members for select to authenticated
  using (public.is_member() or email = lower(coalesce(auth.jwt() ->> 'email', '')));
drop policy if exists "admins manage members" on public.members;
create policy "admins manage members" on public.members for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings','revisions'] loop
    execute format('drop policy if exists "team full access" on public.%I', t);
    execute format('drop policy if exists "team read" on public.%I', t);
    execute format('drop policy if exists "team insert" on public.%I', t);
    execute format('drop policy if exists "team update" on public.%I', t);
    execute format('drop policy if exists "team delete" on public.%I', t);
    execute format('create policy "team read" on public.%I for select to authenticated using (public.is_member())', t);
    execute format('create policy "team insert" on public.%I for insert to authenticated with check (public.can_write())', t);
    execute format('create policy "team update" on public.%I for update to authenticated using (public.can_write()) with check (public.can_write())', t);
    execute format('create policy "team delete" on public.%I for delete to authenticated using (public.can_write())', t);
  end loop;
end $$;

-- ---------- realtime ----------
-- full old rows on delete so other browsers can tell which project a deleted drawing/spec belonged to
alter table public.drawings replica identity full;
alter table public.specs    replica identity full;

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- presence ("who has this project open") runs on a private realtime channel: members only
drop policy if exists "team presence read" on realtime.messages;
create policy "team presence read" on realtime.messages for select to authenticated using (public.is_member());
drop policy if exists "team presence write" on realtime.messages;
create policy "team presence write" on realtime.messages for insert to authenticated with check (public.is_member());

-- ---------- file storage (drawings, specs) ----------
insert into storage.buckets (id, name, public, file_size_limit)
values ('files', 'files', false, 52428800)
on conflict (id) do nothing;

drop policy if exists "team files read" on storage.objects;
create policy "team files read" on storage.objects for select to authenticated
  using (bucket_id = 'files' and public.is_member());
drop policy if exists "team files write" on storage.objects;
create policy "team files write" on storage.objects for insert to authenticated
  with check (bucket_id = 'files' and public.can_write());
drop policy if exists "team files update" on storage.objects;
create policy "team files update" on storage.objects for update to authenticated
  using (bucket_id = 'files' and public.can_write());
drop policy if exists "team files delete" on storage.objects;
create policy "team files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'files' and public.can_write());
