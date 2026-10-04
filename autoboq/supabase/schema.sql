-- AutoBOQ SUBAN CC · Supabase schema
-- Run once in Supabase Dashboard → SQL Editor (safe to re-run).
-- Access model: only emails listed in public.members can read or write anything.

-- ---------- team members (allowlist) ----------
create table if not exists public.members (
  email      text primary key check (email = lower(email)),
  name       text not null default '',
  role       text not null default 'member' check (role in ('admin','member')),
  created_at timestamptz not null default now()
);

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

drop policy if exists "members read" on public.members;
create policy "members read" on public.members for select to authenticated
  using (public.is_member() or email = lower(coalesce(auth.jwt() ->> 'email', '')));
drop policy if exists "admins manage members" on public.members;
create policy "admins manage members" on public.members for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings'] loop
    execute format('drop policy if exists "team full access" on public.%I', t);
    execute format('create policy "team full access" on public.%I for all to authenticated using (public.is_member()) with check (public.is_member())', t);
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
  with check (bucket_id = 'files' and public.is_member());
drop policy if exists "team files update" on storage.objects;
create policy "team files update" on storage.objects for update to authenticated
  using (bucket_id = 'files' and public.is_member());
drop policy if exists "team files delete" on storage.objects;
create policy "team files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'files' and public.is_member());
