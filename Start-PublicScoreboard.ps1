[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ClientCidr,
    [string]$ListenIp,
    [ValidateRange(1024,65535)][int]$Port = 9000
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$selection = Get-Content -LiteralPath (Join-Path $root 'gameserver\local.json') -Raw | ConvertFrom-Json
$runtime = Join-Path $root $selection.active_runtime
$eventId = (Get-Content -LiteralPath (Join-Path $runtime 'config.json') -Raw | ConvertFrom-Json).event_id
$backendPort = [int]$selection.backend_port

if (-not $ListenIp) {
    $interfaces = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address })
    if ($interfaces.Count -ne 1) {
        throw 'Specify -ListenIp because multiple or no routed IPv4 interfaces were found.'
    }
    $ListenIp = [string]$interfaces[0].IPv4Address.IPAddress
}
$assigned = @(Get-NetIPConfiguration | ForEach-Object { $_.IPv4Address } |
    Where-Object { $_ -and $_.IPAddress -eq $ListenIp })
if ($assigned.Count -eq 0) { throw "IP $ListenIp is not assigned to this Windows machine." }

$backend = Invoke-RestMethod -Uri "http://127.0.0.1:$backendPort/health" -TimeoutSec 3
if ($backend.event_id -ne $eventId) { throw 'The running backend does not match the selected event.' }
$occupied = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @($ListenIp, '0.0.0.0') })
if ($occupied.Count) { throw "Port $Port is already listening on $ListenIp or all interfaces." }

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator to create the scoped Windows Firewall rule.'
}
$python = (Get-Command python.exe -ErrorAction Stop).Source
$ruleName = "NOVA scoreboard $eventId $ListenIp $Port"
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
    throw "Firewall rule already exists: $ruleName. Remove the old rule before starting again."
}

$arguments = @('-m','gameserver.public_scoreboard','--host',$ListenIp,'--port',"$Port",
    '--upstream',"http://127.0.0.1:$backendPort")
foreach ($cidr in $ClientCidr) { $arguments += @('--allow',$cidr) }
$rule = $null
try {
    $rule = New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
        -Protocol TCP -LocalAddress $ListenIp -LocalPort $Port -RemoteAddress $ClientCidr -Profile Any
    Write-Host "Scoreboard: http://${ListenIp}:$Port/#score"
    Write-Host "Allowed client IP/CIDR: $($ClientCidr -join ', ')"
    Write-Host 'Keep this window open. Ctrl+C closes the shared listener and removes its firewall rule.'
    Push-Location $root
    try { & $python @arguments }
    finally { Pop-Location }
} finally {
    if ($rule) { Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue }
}
