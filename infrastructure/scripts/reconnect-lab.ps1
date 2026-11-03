# ==============================================================================
#  reconnect-lab.ps1  —  religa o SOC Autonomous Lab após a expiração (1 h)
#  Uso:  powershell -ExecutionPolicy Bypass -File .\reconnect-lab.ps1
#
#  Por que existe: as sessoes do OCI Bastion tem TTL de 1 h. Quando expiram, os
#  tuneis morrem e o endpoint fica cego EM SILENCIO (o servico segue "Running",
#  mas o agente aparece "Never connected" no manager). Este script refaz tudo.
#  Detalhes: docs/adr-001-persistent-agent-connectivity.md
# ==============================================================================

$ErrorActionPreference = 'Continue'
$TerraformDir = 'C:\Users\User\soc-autonomous-lab\infrastructure\terraform'
$Key  = 'C:\Users\User\Desktop\sshkeys\ssh-key-2026-10-08.key'
$Pub  = 'C:\Users\User\Desktop\sshkeys\ssh-key-2026-10-08.key.pub'
$Tmp  = 'C:\Users\User\AppData\Local\Temp\opencode'
$Host_ = 'host.bastion.sa-saopaulo-1.oci.oraclecloud.com'

# Ports: remote -> local
$Ports = @{ 22 = 2222; 1514 = 1514; 1515 = 1515; 443 = 8443 }

Write-Host "`n=== 1. IP atual do manager (nunca assumir o anterior) ===" -ForegroundColor Cyan
Push-Location $TerraformDir
$TargetIP = (terraform output -raw wazuh_private_ip 2>$null).Trim()
Pop-Location
if (-not $TargetIP) {
    Write-Host "ERRO: nao foi possivel ler terraform output. Rode 'terraform apply' antes." -ForegroundColor Red
    exit 1
}
Write-Host "  manager = $TargetIP`n"

Write-Host "=== 2. Limpando tuneis antigos ===" -ForegroundColor Cyan
Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    Write-Host "  encerrado pid=$($_.ProcessId)"
}
Start-Sleep -Seconds 3

Write-Host "`n=== 3. Sessões Bastion (uma por porta-alvo) ===" -ForegroundColor Cyan
$sessions = @{}
foreach ($port in $Ports.Keys) {
    $json = "{`"sessionType`":`"PORT_FORWARDING`",`"targetResourcePrivateIpAddress`":`"$TargetIP`",`"targetResourcePort`":$port}"
    [System.IO.File]::WriteAllText("$Tmp\r-$port.json", $json, (New-Object System.Text.UTF8Encoding($false)))

    $raw = cmd /c "oci --profile DEFAULT bastion session create --bastion-id ocid1.bastion.oc1.sa-saopaulo-1.amaaaaaa6brcn3qa2gt5a2l345uxzqiiq2asvbpsm7g4fagebrz3ppmjawdq --target-resource-details file://$Tmp/r-$port.json --ssh-public-key-file $Pub --display-name SOC-TUN-$port --session-ttl-in-seconds 3600 --wait-for-state SUCCEEDED --max-wait-seconds 300 2>&1"
    $parsed = (($raw -join "`n") -replace '(?s)^.*?(\{[\s\S]*\})\s*$','$1') | ConvertFrom-Json
    $sessions[$port] = $parsed.data.resources[0].identifier
    Write-Host "  port $port -> $($sessions[$port].Substring($sessions[$port].Length-8))"
}

Write-Host "`n=== 4. Subindo os tuneis (com retry: o Bastion replica as sessoes com atraso) ===" -ForegroundColor Cyan
foreach ($port in $Ports.Keys) {
    $local = $Ports[$port]
    $sid   = $sessions[$port]
    $ok = $false
    for ($try = 1; $try -le 12; $try++) {
        $a = @('-i',$Key,'-N','-L',"127.0.0.1:$local`:$TargetIP`:$port",'-p','22',
               '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=NUL','-o','ExitOnForwardFailure=yes',
               '-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3','-o','TCPKeepAlive=yes',"$sid@$Host_")
        $p = Start-Process ssh.exe -ArgumentList $a -WindowStyle Hidden -PassThru `
              -RedirectStandardError "$Tmp\reconnect-$local.err" -RedirectStandardOutput "$Tmp\reconnect-$local.log"
        Start-Sleep -Seconds 6
        if ($p.HasExited) { $p.Dispose(); Start-Sleep -Seconds 20 }
        else { Write-Host "  127.0.0.1:$local -> $TargetIP`:$port  pid=$($p.Id)  (tentativa $try)"; $ok = $true; break }
    }
    if (-not $ok) { Write-Host "  FALHOU a porta $port" -ForegroundColor Red }
}

Write-Host "`n=== 5. Verificacao ===" -ForegroundColor Cyan
Start-Sleep -Seconds 10
$dash = curl.exe -k -s -o NUL -w "%{http_code}" --max-time 30 "https://127.0.0.1:8443/app/login?" 2>$null
Write-Host "  dashboard (https://127.0.0.1:8443) : HTTP $dash"
$conn = Get-NetTCPConnection -RemotePort 1514 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' }
Write-Host "  socket do agente p/ 1514             : $(if($conn){'ESTABLISHED'}else{'DOWN'})"

Write-Host "`n  Estado no manager:" -ForegroundColor Cyan
ssh -i $Key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=25 -o BatchMode=yes `
    ubuntu@127.0.0.1 "sudo /var/ossec/bin/agent_control -lc 2>/dev/null | grep -E 'ID: 00'" 2>$null

Write-Host "`n=== 6. Se o FIM nao disparar (C:\SOC-Lab) ===" -ForegroundColor Cyan
Write-Host "  O agente so monitora diretorios realtime que EXISTAM no startup."
Write-Host "  Se C:\SOC-Lab foi criado depois, force o re-registro SEM elevacao local:"
Write-Host "    ssh -p 2222 ubuntu@127.0.0.1 `"sudo /var/ossec/bin/agent_control -R -u 002`"` -ForegroundColor Yellow
Write-Host "`n=== Sessões expiram em 1 h — rerun este script quando o agente cair ===" -ForegroundColor Cyan
