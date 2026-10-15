# MeKoData CTF — IDOR tra cứu điểm (four team boxes)

One CyberRangeCZ Sandbox Definition. Create **one pool of size 1** from this repository root. The sandbox contains four Kali team VMs on a shared LAN plus a gateway router. **Each team VM self-hosts its own point-lookup (tra cứu điểm) web portal with a deliberate IDOR, and each hides its own flag.**

| Node | IP | Portal | Flag |
| --- | --- | --- | --- |
| team01 | `10.80.0.11` | `http://10.80.0.11/` | `MeKoDataCTF{team01_…}` |
| team02 | `10.80.0.12` | `http://10.80.0.12/` | `MeKoDataCTF{team02_…}` |
| team03 | `10.80.0.13` | `http://10.80.0.13/` | `MeKoDataCTF{team03_…}` |
| team04 | `10.80.0.14` | `http://10.80.0.14/` | `MeKoDataCTF{team04_…}` |
| checker | `10.80.0.30` | `http://10.80.0.30:8080/` | flag validator (scaffold) |
| gateway | `10.80.0.1` | Routing only | — |

**Credentials.**

Each team VM has **two separate local accounts** (both with `sudo` for patching), plus the web portal login:

- **Topology console login:** `teamNN / teamNN` (e.g. `team01 / team01`). Used at the topology console. This account is **blocked from SSH** (`DenyUsers`).
- **SSH login:** `mekoNN / mekoNN` (e.g. `meko01 / meko01`), e.g. `ssh meko01@10.80.0.11`. SSH is **password-only** (pubkey disabled) so it always prompts; the console `teamNN` account cannot be used over SSH.
- **Web portal login:** `student / teamNN_mekodatactf_2026_test1`.

All of these live in `team_secrets` in `provisioning/group_vars/all.yml` (`console_password`, `ssh_user`, `ssh_password`, `password`). The platform `user-access` account stays for the GUI tunnel. These are demo values — replace before any real event.

> Note: if your CyberRangeCZ console itself logs in over SSH as `teamNN`, remove the `DenyUsers {{ inventory_hostname }}` line, since it would block that console too.

Passwords and flags live in `provisioning/group_vars/all.yml` (`team_secrets`, `team_flags`) — replace them before any real event.

## The vulnerability and the flag chain

The portal lets a student view their own score records. `GET /api/scores/<record_id>` performs **no owner authorization** (classic IDOR). The flag for each box sits in an internal teacher "audit" record that is never listed for the student, reachable only by changing the `record_id`.

Four steps to the flag:

1. Log in, then **refresh** — the browser loads `/static/point.js`. Read its API map and the internal notes.
2. `GET /api/me` and `GET /api/scores` reveal your own `record_id`s (from 1001).
3. Change the id in `GET /api/scores/<record_id>` — it returns other students' records (IDOR confirmed).
4. point.js documents an audit range at `record_id` 9000+. `GET /api/scores/9001` returns a `remark` field containing `MeKoDataCTF{teamNN_xxxxxxxx}`.

The fixed build (`lab_enforce_owner: true`) adds the ownership check and returns `403` for peer and audit records.

## Checker / flag-validator server

A separate Debian host `checker` (`10.80.0.30`) runs a small flag-validator scaffold on port 8080, so you can grow a scoreboard/checker later without changing the topology:

```
GET http://10.80.0.30:8080/health
GET http://10.80.0.30:8080/validate?team=team01&flag=MeKoDataCTF{team01_9f3a7c21}
    -> {"valid": true, "team": "team01"}
```

Known flags come from `team_flags` in `provisioning/group_vars/all.yml` (keep it in sync with `team_secrets[*].flag`). Replace `app/checker.py` with your real checker; the service unit and `/etc/mekodata-checker/config.json` path stay the same.

## Deploy

1. Put this directory at the root of a Git repository accessible to CyberRangeCZ. `topology.yml` and `provisioning/` must be at the repository root.
2. Create one Sandbox Definition from that Git URL and revision. Create one pool with **size 1**, then Allocate it. The provisioning playbook configures all four team hosts and verifies each portal responds before it finishes.
3. Import `training-definition.json`, review and release it, then create one cloud Training Instance and assign the pool.

The `kali` image and `standard.kali` flavor in `topology.yml` must exist in your cloud. The platform runner needs Ansible, the `user-access` role, and `ansible.posix` from `provisioning/requirements.yml`. The four host IPs and gateway subnet must not conflict with the platform's management network.

## Verify inside the sandbox

On any team VM, the local portal must answer and serve its API map:

```bash
curl --noproxy '*' -fsS http://127.0.0.1/health
curl --noproxy '*' -fsS http://127.0.0.1/static/point.js | grep /api/scores/
```

The four team portals are reachable across the LAN (`http://10.80.0.11/` … `http://10.80.0.14/`). HTTP uses port 80 without adding `:80` to the URL. A private `10.x.x.x` URL is accessible only from the lab network or an approved tunnel.

## Local source checks

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m unittest discover -s tests -v
```
