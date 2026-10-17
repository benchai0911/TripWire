create table if not exists scans (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  bot_name text not null,
  mode text not null check (mode in ('baseline','hardened_prompt','hardened_prompt_firewall','hardened_prompt_firewall_guard')),
  security_score numeric not null,
  grade text not null,
  over_refusal_rate numeric,
  firewall_fp_rate numeric,
  total_attacks int not null,
  system_prompt_hash text not null,
  saved_system_prompt text
);

create table if not exists attack_results (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references scans(id) on delete cascade,
  attack_id text not null,
  category text not null,
  verdict text not null,
  source text not null,
  canary_leaked boolean not null default false,
  blocked_by_firewall boolean not null default false,
  firewall_score numeric,
  judge_reason text,
  response_excerpt text
);

create index if not exists attack_results_scan_id_idx on attack_results(scan_id);
alter table scans enable row level security;
alter table attack_results enable row level security;
-- No public policies. Only the server-side service key can read/write.

-- Also updates the mode constraint on existing installations.
alter table scans drop constraint if exists scans_mode_check;
alter table scans add constraint scans_mode_check check (mode in ('baseline','hardened_prompt','hardened_prompt_firewall','hardened_prompt_firewall_guard'));
