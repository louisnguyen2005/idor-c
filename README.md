# NOVA MART Attack–Defense CTF on CyberRangeCZ

This source provisions one sandbox with four team VMs, a shared organizer server and a routing gateway. Every team VM runs the two isolated NOVA MART instances declared in `deployment.json`. An external Windows gateway and Python backend/checker measure service SLA and score captured flags.

Default schedule: **1 hour, 2 rounds of 30 minutes, 1 service per round, 120 seconds per tick, 15 ticks per round, 30 ticks total**. UP earns 1 SLA/tick; DOWN, MUMBLE, ERROR or a missed tick earns 0. Each tick places a private order flag when the complete shop workflow succeeds. Capturing an active enemy flag earns 100 points and removes 100 points from its owner. Flags last three ticks within their service round.

NOVA MART includes five deliberate challenge paths: SQL injection in catalog search, CAPTCHA bypass, stored XSS in reviews, CSRF in order sharing, and merchant password brute force. The source has switches for all five so defenders can patch and test their instance. The tick checker uses ordinary registration, solves the real CAPTCHA, creates the order, and verifies current and unexpired flags. The shop SQLite database is separate per team and round.

## Configuration and upload

Edit `deployment.json` for team IDs/node IPs, images/flavors, service ports, checker mode and schedule. The sample SSH passwords are isolated-lab examples; choose your event's passwords before uploading a private repository.

```powershell
py -3 -m pip install -r requirements-dev.txt
py -3 -m gameserver.definition --write
py -3 -m gameserver.definition
py -3 -m unittest discover -s tests -v
py -3 -m gameserver.package --output ..\LVTN-merged-cyberrange-ready.zip
```

The generator synchronizes topology, provisioning variables, ACL, training text and examples. Provisioning rejects a revision whose manifest and generated variables differ. Extract the ZIP into a clean source folder: `topology.yml`, `deployment.json` and `provisioning/` must be at the Git repository root used by the CyberRangeCZ Sandbox Definition. Select the new Git revision and create/reprovision a pool of size 1.

The ZIP builder excludes `.git`, private keys, allocation-specific gateway configs, credentials, runtime SQLite files, logs and checker results. It produces a SHA-256 file beside the ZIP. It does not upload or change a running pool.

## After CyberRangeCZ allocates the new sandbox

Download/extract its **user SSH access ZIP** into your Windows `.ssh` folder. Keep the config and matching key together. Configure the allocation:

```powershell
.\Configure-Deployment.ps1 -SshConfig "$env:USERPROFILE\.ssh\<CURRENT-ALLOCATION-user-config>" -Access local
```

This derives pool/sandbox IDs, generates all forward/checker targets and password-login team aliases, and creates a **new SQLite database in READY state**. Local access binds gateway listeners to `127.0.0.1`; it works for a checker on the same Windows machine and needs no inbound LAN firewall rule.

To share the scoreboard of an event already running in local mode, run
`Start-PublicScoreboard.ps1 -ListenIp <ORGANIZER-LAN-IP> -ClientCidr <PLAYER-IP>/32`
in an Administrator PowerShell window. It opens only the scoreboard, public
score APIs and authenticated flag submission on the selected network IP;
the backend and checker continue on loopback. See `docs/DEPLOYMENT.vi.md`.

Then verify SSH fingerprints and forwarding using [the gateway guide](CyberRangeCZ-Windows-Gateway/README.md). Start the stack when ready to start the competition clock:

```powershell
.\gameserver\Start-Stack.ps1
```

Open `http://127.0.0.1:9000/` (or the backend port selected during configuration). The stack starts/reuses the SSH gateway, runs preflight, starts backend/worker and starts the event. Keep its window open. Ctrl+C stops its child processes; event time continues.

For LAN access use `-Access lan -GatewayIp auto -ClientCidr <CONFIRMED_CIDR>` during configuration. The auto IP follows the route to the SSH landing host. Apply scoped Windows Firewall rules separately with `Apply-GatewayFirewall.ps1` in an elevated PowerShell session. The shared organizer service is excluded from contestant firewall ports.

## Offline demo

```powershell
py -3 -m gameserver.demo --fast
```

Open `http://127.0.0.1:19000/`. Fast mode preserves 30 ticks but uses 5 seconds/tick, so the run finishes in about 2.5 minutes. Omit `--fast` for the real one-hour schedule. Tick 3 simulates an outage on the second team; tick 4 recovers. Each successful functional check creates a private order flag. The demo uses local shops and SQLite; it does not contact CyberRangeCZ.

## Database and operations

The central database is **SQLite in WAL mode**, created automatically on the Windows backend under the selected `gameserver/runtime-sla-<event>/competition.sqlite`. The checker communicates through an authenticated API; only the backend opens this database. Application databases remain separate inside each team VM/service.

`gameserver/local.json` selects the active event; scripts resolve paths and backend ports from it. A running event's rules/allocation are frozen. Configure a new event after changing the allocation or schedule. Online backup uses `py -3 -m gameserver.control backup --destination <NEW_ABSOLUTE_FILE>`; finish uses `py -3 -m gameserver.control finish`.

Full Vietnamese instructions: [deployment and handover](docs/DEPLOYMENT.vi.md), [tick checker, flags and monitoring](gameserver/README.vi.md). The public scoreboard is `/`; the token-protected operations monitor is `/monitor`. Team tokens live in the private runtime folder and must be delivered to teams separately. `checker/auto_check.py` remains a separate legacy diagnostic checker and does not award competition points.

The GitHub workflow checks source/tests and Ansible syntax on Linux after the source is pushed. Creating VMs, checking cloud image/flavor availability and confirming live service reachability still happen in CyberRangeCZ.
