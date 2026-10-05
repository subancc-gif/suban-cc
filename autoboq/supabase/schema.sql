-- AutoBOQ SUBAN CC · schema for the HR Supabase project (shared login with the HR app)
-- Run in the HR project: Supabase Dashboard → SQL Editor, after the HR setup.sql and update-2.sql. Safe to re-run.
-- Everything lives in its own schema "autoboq", so no table of the HR app is touched or renamed.
-- After running: Dashboard → Project Settings → Data API → "Exposed schemas" → add  autoboq  → Save.
--
-- Access model (read live from the HR table public.employees, so joins, leavers and role changes apply at once):
--   HR role ผู้บริหาร/HR  → admin   (edit everything, manage who can use AutoBOQ)
--   HR role หัวหน้างาน     → member  (edit)
--   HR role พนักงาน        → no access, unless an admin grants it on the Members page
-- An admin can override any person: admin / member (edit) / viewer (read only, e.g. QC or a customer account) / none.
-- A deleted employee loses access immediately (their override row is removed with them).

create schema if not exists autoboq;
grant usage on schema autoboq to authenticated;

-- ---------- per-person overrides (no row = follow the HR role) ----------
create table if not exists autoboq.members (
  emp_id     text primary key references public.employees(id) on delete cascade,
  role       text not null check (role in ('admin','member','viewer','none')),
  created_at timestamptz not null default now()
);

-- ---------- who am I ----------
create or replace function autoboq.my_role()
returns text language sql stable security definer set search_path = '' as $$
  select case coalesce(m.role, 'auto')
           when 'none' then null
           when 'auto' then case e.role when 'ผู้บริหาร/HR' then 'admin' when 'หัวหน้างาน' then 'member' else null end
           else m.role
         end
  from public.employees e
  left join autoboq.members m on m.emp_id = e.id
  where e.user_id = auth.uid();
$$;

create or replace function autoboq.is_member()
returns boolean language sql stable security definer set search_path = '' as $$
  select autoboq.my_role() is not null;
$$;

create or replace function autoboq.is_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(autoboq.my_role() = 'admin', false);
$$;

-- write access: admins and members. 'viewer' can read everything but change nothing.
create or replace function autoboq.can_write()
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(autoboq.my_role() in ('admin','member'), false);
$$;

-- the signed-in person, for the app header and the "must set PIN first" check
create or replace function autoboq.me()
returns table(emp_id text, name text, pos text, access text, must_change boolean)
language sql stable security definer set search_path = '' as $$
  select e.id, e.name, e.pos, autoboq.my_role(), e.must_change
  from public.employees e where e.user_id = auth.uid();
$$;

-- people list for the Members page (admin: every employee; others: only people who can use AutoBOQ, for display names)
create or replace function autoboq.team()
returns table(emp_id text, name text, pos text, site text, hr_role text, override text, access text)
language sql stable security definer set search_path = '' as $$
  with t as (
    select e.id as emp_id, e.name, e.pos, e.site, e.role as hr_role, m.role as override,
           case coalesce(m.role, 'auto')
             when 'none' then null
             when 'auto' then case e.role when 'ผู้บริหาร/HR' then 'admin' when 'หัวหน้างาน' then 'member' else null end
             else m.role
           end as access
    from public.employees e
    left join autoboq.members m on m.emp_id = e.id
  )
  select t.emp_id, t.name, t.pos, t.site, t.hr_role, t.override, t.access
  from t
  where autoboq.is_admin() or (autoboq.is_member() and t.access is not null)
  order by t.emp_id;
$$;

-- admin sets one person's override: 'auto' (follow HR role), 'admin', 'member', 'viewer' or 'none'
create or replace function autoboq.set_access(target text, new_role text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not autoboq.is_admin() then raise exception 'not allowed' using errcode = '42501'; end if;
  if target = (select e.id from public.employees e where e.user_id = auth.uid()) then
    raise exception 'cannot change your own access';
  end if;
  if new_role = 'auto' then
    delete from autoboq.members where emp_id = target;
  elsif new_role in ('admin','member','viewer','none') then
    insert into autoboq.members(emp_id, role) values (target, new_role)
      on conflict (emp_id) do update set role = excluded.role;
  else
    raise exception 'unknown role';
  end if;
end $$;

-- ---------- app data (JSON bodies mirror the app's in-memory shapes) ----------
create table if not exists autoboq.projects (
  id         text primary key,
  info       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists autoboq.boq (
  project_id text not null references autoboq.projects(id) on delete cascade,
  code       text not null check (code in ('A','B','C','D','E','F','G','H')),
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (project_id, code)
);

create table if not exists autoboq.drawings (
  id         text primary key,
  project_id text not null references autoboq.projects(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists drawings_project_idx on autoboq.drawings(project_id);

create table if not exists autoboq.specs (
  id         text primary key,
  project_id text not null references autoboq.projects(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists specs_project_idx on autoboq.specs(project_id);

-- price library: one row per BOQ category, data = {items:[...]}
create table if not exists autoboq.library (
  code       text primary key check (code in ('A','B','C','D','E','F','G','H')),
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

-- shared settings, e.g. key 'company' = quotation letterhead
create table if not exists autoboq.settings (
  key        text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);

-- quotation snapshots: one row per issued revision
create table if not exists autoboq.revisions (
  id         text primary key,
  project_id text not null references autoboq.projects(id) on delete cascade,
  data       jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists revisions_project_idx on autoboq.revisions(project_id, created_at desc);

-- running document numbers (QT-2569-001, INV-2569-001), only reachable through next_doc_no()
create table if not exists autoboq.counters (
  key   text primary key,
  value integer not null default 0
);

create or replace function autoboq.next_doc_no(prefix text, yr integer)
returns text language plpgsql security definer set search_path = '' as $$
declare n integer; k text;
begin
  if not autoboq.can_write() then raise exception 'not allowed' using errcode = '42501'; end if;
  if upper(prefix) not in ('QT','INV') then raise exception 'unknown prefix'; end if;
  k := upper(prefix) || '-' || yr;
  insert into autoboq.counters(key, value) values (k, 1)
    on conflict (key) do update set value = autoboq.counters.value + 1
    returning value into n;
  return k || '-' || lpad(n::text, 3, '0');
end $$;

-- merge a patch into projects.info atomically (two people editing different fields never overwrite each other)
create or replace function autoboq.merge_project_info(pid text, patch jsonb)
returns void language sql security invoker set search_path = '' as $$
  update autoboq.projects set info = info || patch, updated_at = now() where id = pid;
$$;

-- keep updated_at fresh on every write
create or replace function autoboq.touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end $$;

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings'] loop
    execute format('drop trigger if exists touch_%1$s on autoboq.%1$s', t);
    execute format('create trigger touch_%1$s before update on autoboq.%1$s for each row execute function autoboq.touch_updated_at()', t);
  end loop;
end $$;

-- ---------- row level security ----------
alter table autoboq.members   enable row level security;
alter table autoboq.projects  enable row level security;
alter table autoboq.boq       enable row level security;
alter table autoboq.drawings  enable row level security;
alter table autoboq.specs     enable row level security;
alter table autoboq.library   enable row level security;
alter table autoboq.settings  enable row level security;
alter table autoboq.revisions enable row level security;
alter table autoboq.counters  enable row level security;

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings','revisions'] loop
    execute format('drop policy if exists "team read" on autoboq.%I', t);
    execute format('drop policy if exists "team insert" on autoboq.%I', t);
    execute format('drop policy if exists "team update" on autoboq.%I', t);
    execute format('drop policy if exists "team delete" on autoboq.%I', t);
    execute format('create policy "team read" on autoboq.%I for select to authenticated using (autoboq.is_member())', t);
    execute format('create policy "team insert" on autoboq.%I for insert to authenticated with check (autoboq.can_write())', t);
    execute format('create policy "team update" on autoboq.%I for update to authenticated using (autoboq.can_write()) with check (autoboq.can_write())', t);
    execute format('create policy "team delete" on autoboq.%I for delete to authenticated using (autoboq.can_write())', t);
  end loop;
end $$;

-- ---------- grants ----------
revoke all on all functions in schema autoboq from public, anon;
grant execute on all functions in schema autoboq to authenticated;
revoke all on all tables in schema autoboq from anon;
grant select, insert, update, delete on all tables in schema autoboq to authenticated;
-- overrides and counters are reachable only through the functions above
revoke all on autoboq.members, autoboq.counters from authenticated;

-- ---------- realtime ----------
alter table autoboq.drawings replica identity full;
alter table autoboq.specs    replica identity full;

do $$
declare t text;
begin
  foreach t in array array['projects','boq','drawings','specs','library','settings'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'autoboq' and tablename = t) then
      execute format('alter publication supabase_realtime add table autoboq.%I', t);
    end if;
  end loop;
end $$;

-- presence ("who has this project open") runs on a private realtime channel: AutoBOQ users only
drop policy if exists "autoboq presence read" on realtime.messages;
create policy "autoboq presence read" on realtime.messages for select to authenticated using (autoboq.is_member());
drop policy if exists "autoboq presence write" on realtime.messages;
create policy "autoboq presence write" on realtime.messages for insert to authenticated with check (autoboq.is_member());

-- ---------- file storage (drawings, specs) ----------
insert into storage.buckets (id, name, public, file_size_limit)
values ('autoboq-files', 'autoboq-files', false, 52428800)
on conflict (id) do nothing;

drop policy if exists "autoboq files read" on storage.objects;
create policy "autoboq files read" on storage.objects for select to authenticated
  using (bucket_id = 'autoboq-files' and autoboq.is_member());
drop policy if exists "autoboq files write" on storage.objects;
create policy "autoboq files write" on storage.objects for insert to authenticated
  with check (bucket_id = 'autoboq-files' and autoboq.can_write());
drop policy if exists "autoboq files update" on storage.objects;
create policy "autoboq files update" on storage.objects for update to authenticated
  using (bucket_id = 'autoboq-files' and autoboq.can_write());
drop policy if exists "autoboq files delete" on storage.objects;
create policy "autoboq files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'autoboq-files' and autoboq.can_write());

notify pgrst, 'reload schema';
