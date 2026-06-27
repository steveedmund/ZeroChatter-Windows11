<#
====
 Network Traffic Monitor v4.3
 Author:  Steve  (v4.2/4.3 noise-filtering additions)
 Version: 4.3
 Date:    2026-06-25

 PURPOSE:
   Capture ALL network activity with per-process and per-destination detail
   for 48-72 hours to validate hardening effectiveness - AND automatically
   strip out the LAN broadcast/multicast "subnet noise" from other devices
   (e.g. the Proxmox box on the same wired segment) that inflated the raw NIC
   counters in earlier runs and made the v2.0/v2.1 result look like a regression.

 ----------------------------------------------------------------------------
 WHY v4.3 REPLACES THE v4.2 pktmon APPROACH (this is the fix for the
 "pktmon failed at launch, twice" problem you saw):
   v4.2 tried to get the clean (noise-free) byte count from a built-in `pktmon`
   counter session. That turned out to be unreliable for two reasons:
     (a) pktmon's counter output schema is undocumented and varies by Windows
         build, so the parser could not always read it; and
     (b) the start-up probe disabled the feature whenever the first 0.5 s sample
         read ZERO bytes - which is exactly what happens on an idle link - so it
         "failed" even when pktmon itself was fine.
   v4.3 drops pktmon entirely and instead reads the unicast / broadcast /
   multicast byte split that the NIC ITSELF maintains, exposed natively by
   Get-NetAdapterStatistics (MSFT_NetAdapterStatisticsSettingData):
       ReceivedUnicastBytes / ReceivedBroadcastBytes / ReceivedMulticastBytes
       SentUnicastBytes     / SentBroadcastBytes     / SentMulticastBytes
   This is GROUND TRUTH from the adapter, needs no extra session, no admin-only
   tool, and no fragile text parsing. It is the same cmdlet the monitor already
   used for the raw totals, so it is guaranteed to work on this rig.

 HOW THE NOISE FILTER NOW WORKS (no configuration required):
   * CLEAN  = unicast bytes  (Received/SentUnicastBytes). Real traffic to/from
              this rig - the ONLY thing that can traverse Iridium.
   * NOISE  = broadcast + multicast bytes. Frames the segment floods at this NIC
              (Proxmox cluster chatter, ARP, mDNS, LLMNR, SSDP, etc.). The rig
              receives them at Layer 2 but they NEVER leave over a WAN link.
   The Proxmox burst that made earlier runs look bad lands entirely in the NOISE
   bucket and is reported separately, so the CLEAN number is finally trustworthy.

 RETAINED FROM v4.2:
   1. AUTO TEST-RIG IDENTITY: auto-detects this machine's own IPv4 address(es).
   2. PER-CONNECTION CATEGORY TAGGING: every connection carries a Category column
      (WAN / LAN / Multicast / Broadcast / LinkLocal / Loopback / Listen) and a
      NoiseSource flag (-ExcludeNoiseIPs). v4.3 FIX: the IPv6 unspecified address
      "::" and IPv4 "0.0.0.0"/"*" (listening sockets) are now tagged Listen, NOT
      WAN - in the last capture 9,145 idle listener rows were mis-counted as WAN.
   3. FINAL REPORT prints RAW vs CLEAN(unicast) vs NOISE(broadcast+multicast)
      with 30-day projections so the broadcast inflation is visible and quantified.

 v4.1 FIX vs v4 (retained):
   - FIXED Int32 overflow crash: all clamps use [math]::Max([long]0, ...) so the
     Max(long,long) overload is selected and full 64-bit deltas pass.

 USAGE:
   .\NetMonitor_v4.3.ps1
   .\NetMonitor_v4.3.ps1 -IntervalSeconds 30 -LogPath "C:\BUILDS\SCRIPTS\NetMonitor"
   # Flag a known noise source (e.g. the Proxmox box) in the connections CSV:
   .\NetMonitor_v4.3.ps1 -ExcludeNoiseIPs "192.168.8.1","192.168.8.10"
   # Override auto-detection of this rig's IPs if needed:
   .\NetMonitor_v4.3.ps1 -TestRigIPs "192.168.8.158"
====
#>

#Requires -RunAsAdministrator
param(
    [int]$IntervalSeconds = 30,
    [string]$LogPath      = "C:\BUILDS\SCRIPTS\NetMonitor",
    [int]$MaxLogSizeMB    = 2048,

    # v4.2: IPs of OTHER devices whose traffic should be flagged as subnet noise
    # (e.g. the Proxmox server). Connections to/from these are tagged
    # NoiseSource=True so they can be excluded from WAN analysis. Broadcast /
    # multicast is already separated out by the unicast NIC counters regardless.
    [string[]]$ExcludeNoiseIPs = @(),

    # v4.2: Override the auto-detected test-rig IPv4 address(es). Leave empty to
    # auto-detect every IPv4 bound to a physically-connected adapter.
    [string[]]$TestRigIPs = @(),

    # v4.3: Set $false to skip the native unicast/broadcast/multicast clean split
    # (e.g. on a NIC whose driver does not populate the per-cast counters). RAW
    # NIC totals + connection Category tagging still run.
    [bool]$EnableCleanStats = $true
)

# ====
# PRE-FLIGHT
# ====

# Ensure the log directory exists before anything tries to write to it.
if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

# Remove stale header-only / 0-byte CSVs (<=200 bytes) left by failed prior runs
# so they don't accumulate and pollute later analysis.
$staleCsvPatterns = @('connections_*.csv','process_bytes_*.csv','dns_queries_*.csv',
                    'hourly_summary_*.csv','interface_snapshots_*.csv')
foreach ($pattern in $staleCsvPatterns) {
    Get-ChildItem -Path $LogPath -Filter $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -le 200 } |
        ForEach-Object {
            Write-Host "  Removing stale CSV: $($_.Name) ($($_.Length) bytes)" -ForegroundColor DarkGray
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
}

# Enable the DNS-Client operational log if it's off, so the ETW DNS job
# (Event 3006) has events to read. Fall back to cache polling if unavailable.
try {
    $dnsLog = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction Stop
    if (-not $dnsLog.IsEnabled) {
        Write-Host "Enabling Microsoft-Windows-DNS-Client/Operational log..." -ForegroundColor Yellow
        $dnsLog.IsEnabled = $true
        $dnsLog.SaveChanges()
    }
} catch {
    Write-Host "WARNING: Could not enable DNS-Client operational log: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "         DNS capture will fall back to cache polling (less complete)." -ForegroundColor Red
}

# Build the per-run, timestamped output file paths.
$startTime  = Get-Date
$dateStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$connLog    = Join-Path $LogPath "connections_$dateStamp.csv"
$processLog = Join-Path $LogPath "process_bytes_$dateStamp.csv"
$dnsQueryLog= Join-Path $LogPath "dns_queries_$dateStamp.csv"
$summaryLog = Join-Path $LogPath "hourly_summary_$dateStamp.csv"
$snapshotLog= Join-Path $LogPath "interface_snapshots_$dateStamp.csv"
$unicastLog = Join-Path $LogPath "wan_unicast_$dateStamp.csv"   # v4.3: clean (unicast) vs noise (bcast/mcast) byte series

# State carried across loop iterations.
$dnsCache          = @{}   # IP -> resolved hostname (memoized)
$prevProcessBytes  = @{}   # PID -> prior IO counters (for deltas)
$prevIfaceBytes    = @{}   # iface -> prior NIC counters (for deltas)
$prevIfaceSnapshot = @{}   # iface -> two-iterations-ago counters (console delta)
$hourlyBucket      = @{}   # iface -> accumulated send/recv for the hour
$lastHour          = (Get-Date).Hour
$resetCount        = 0
$dnsJob            = $null

# v4.3 state -------------------------------------------------------------------
$cleanStatsActive  = $false        # set true once the NIC per-cast counters look usable
$prevCast          = @{}           # iface -> prior @{UniS;UniR;BcastR;McastR} (for deltas)
$cleanTotalSend    = [long]0       # running CLEAN (unicast) totals since start
$cleanTotalRecv    = [long]0
$noiseTotalRecv    = [long]0       # running NOISE (broadcast+multicast) recv totals
$noiseTotalSend    = [long]0       # running NOISE (broadcast+multicast) send totals
$rawTotalSend      = [long]0       # running RAW NIC totals since start (for report parity)
$rawTotalRecv      = [long]0
# Normalize the noise-source list into a fast lookup.
$noiseSet = @{}
foreach ($ip in $ExcludeNoiseIPs) { if ($ip) { $noiseSet[$ip.Trim()] = $true } }

# ====
# HELPERS
# ====

# Resolve an IP to a hostname, caching results. Skips loopback/link-local/zero.
function Resolve-Cached {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $IP }
    if ($IP -match "^(127\.|::1|0\.0\.0|169\.254\.)") { return $IP }
    if ($dnsCache.ContainsKey($IP)) { return $dnsCache[$IP] }
    try {
        $name = [System.Net.Dns]::GetHostEntry($IP).HostName
        $dnsCache[$IP] = $name
    } catch {
        $dnsCache[$IP] = ""
    }
    return $dnsCache[$IP]
}

# Snapshot cumulative per-process I/O (disk + net + IPC) byte counters.
# v4: sourced from Win32_Process (CIM) because Get-Process objects expose no
# .IO member. Returns PID -> @{ Name; Send; Recv }.
function Get-ProcessNetIO {
    $result = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($null -ne $_.ProcessId -and $_.ProcessId -ne 0) {
                $result[[int]$_.ProcessId] = @{
                    Name = ($_.Name -replace '\.exe$','')   # strip .exe for name matching/colors
                    Send = [long]$_.WriteTransferCount
                    Recv = [long]$_.ReadTransferCount
                }
            }
        } catch { }
    }
    return $result
}

# Snapshot cumulative per-interface NIC byte counters (ground truth).
# v4.3: also captures the unicast / broadcast / multicast byte split that the
# adapter maintains natively (MSFT_NetAdapterStatisticsSettingData). Some props
# can be $null on certain drivers, so each is coalesced to 0 defensively.
function Get-InterfaceBytes {
    $result = @{}
    Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
        $u = $_
        $toLong = { param($v) if ($null -eq $v) { [long]0 } else { [long]$v } }
        $result[$u.Name] = @{
            Sent      = & $toLong $u.SentBytes
            Received  = & $toLong $u.ReceivedBytes
            # CLEAN (unicast) - real to/from-this-rig traffic, can traverse WAN.
            UniSent   = & $toLong $u.SentUnicastBytes
            UniRecv   = & $toLong $u.ReceivedUnicastBytes
            # NOISE (broadcast + multicast) - segment flooding, never leaves WAN.
            BcastRecv = & $toLong $u.ReceivedBroadcastBytes
            McastRecv = & $toLong $u.ReceivedMulticastBytes
            BcastSent = & $toLong $u.SentBroadcastBytes
            McastSent = & $toLong $u.SentMulticastBytes
        }
    }
    return $result
}

# v4.2: Classify a remote IP into a traffic category. This is the pure-PowerShell
# half of the noise filter - it lets the connections CSV be sliced to WAN-only
# without any external tool. Categories:
#   Loopback   127.0.0.0/8, ::1
#   LinkLocal  169.254.0.0/16, fe80::/10
#   Multicast  224.0.0.0/4, ff00::/8
#   Broadcast  255.255.255.255 (and x.x.x.255 heuristic)
#   LAN        RFC1918 (10/8, 172.16/12, 192.168/16) + RFC4193 fc00::/7
#   WAN        everything else (the only traffic that traverses Iridium)
function Get-IPCategory {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return "Listen" }
    # v4.3 FIX: unspecified / wildcard addresses are LISTENING sockets, not WAN.
    # (Last capture had 9,145 "::" listener rows wrongly counted as WAN.)
    if ($IP -eq "::" -or $IP -eq "0.0.0.0" -or $IP -eq "*") { return "Listen" }
    if ($IP -eq "255.255.255.255")                 { return "Broadcast" }
    if ($IP -match "^127\." -or $IP -eq "::1")      { return "Loopback" }
    if ($IP -match "^169\.254\." -or $IP -match "^fe80:")        { return "LinkLocal" }
    if ($IP -match "^(22[4-9]|23[0-9])\." -or $IP -match "^ff[0-9a-fA-F][0-9a-fA-F]:") { return "Multicast" }
    if ($IP -match "^10\." -or
        $IP -match "^192\.168\." -or
        $IP -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or
        $IP -match "^(fc|fd)[0-9a-fA-F][0-9a-fA-F]:") { return "LAN" }
    if ($IP -match "\.255$") { return "Broadcast" }   # heuristic: directed broadcast
    return "WAN"
}

# ====
# v4.2 PRE-FLIGHT : TEST-RIG IDENTITY (used for connection Category/NoiseSource)
# ====
# Determine THIS rig's own IPv4 address(es). Used to tag the connections CSV;
# the unicast/broadcast/multicast split itself is measured per-adapter by the
# NIC counters and needs no IP filter.
if ($TestRigIPs.Count -eq 0) {
    try {
        $TestRigIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
                $_.PrefixOrigin -ne 'WellKnown'
            } | Select-Object -ExpandProperty IPAddress -Unique
    } catch { }
}
if (-not $TestRigIPs -or $TestRigIPs.Count -eq 0) {
    Write-Host "NOTE: Could not auto-detect a test-rig IPv4 address (connection tagging" -ForegroundColor DarkYellow
    Write-Host "      will still work; pass -TestRigIPs to label local rows explicitly)." -ForegroundColor DarkYellow
}

# ====
# MAIN LOOP
# ====
Write-Host ""
Write-Host "====" -ForegroundColor Cyan
Write-Host "  Network Monitor v4.3  (native unicast/broadcast/multicast split)" -ForegroundColor Cyan
Write-Host "  Logging to: $LogPath" -ForegroundColor Yellow
Write-Host "  Interval: ${IntervalSeconds}s" -ForegroundColor Yellow
Write-Host "  DNS capture: ETW (Microsoft-Windows-DNS-Client/3006)" -ForegroundColor Yellow
Write-Host ("  Test-rig IP(s): {0}" -f ($(if ($TestRigIPs) { $TestRigIPs -join ', ' } else { 'n/a' }))) -ForegroundColor Yellow
Write-Host ("  Noise-source IP(s) flagged: {0}" -f ($(if ($ExcludeNoiseIPs) { $ExcludeNoiseIPs -join ', ' } else { 'none' }))) -ForegroundColor Yellow
Write-Host ("  Clean unicast counter (NIC stats): {0}" -f ($(if ($EnableCleanStats) { 'ENABLED' } else { 'disabled' }))) -ForegroundColor Yellow
Write-Host "  Press Ctrl+C to stop (summary will print)" -ForegroundColor Yellow
Write-Host "====" -ForegroundColor Cyan
Write-Host ""

$iteration = 0

try {
    # Create CSVs + headers INSIDE the try block so a pre-loop failure leaves
    # no orphan files behind.
    "Timestamp,PID,ProcessName,Protocol,LocalAddr,LocalPort,RemoteAddr,RemotePort,State,ResolvedName,Category,NoiseSource" |
        Out-File $connLog -Encoding UTF8
    "Timestamp,PID,ProcessName,TotalIOWrite,TotalIORead,WriteDelta,ReadDelta" |
        Out-File $processLog -Encoding UTF8
    "Timestamp,QueryName,QueryType,ResolvingPID,ProcessName" |
        Out-File $dnsQueryLog -Encoding UTF8
    "Timestamp,Hour,TotalSendMB,TotalRecvMB,TopProcess,TopProcessMB,UniqueRemoteIPs,UniqueRemoteDomains" |
        Out-File $summaryLog -Encoding UTF8
    "Timestamp,Interface,BytesSent,BytesReceived,SendDeltaKB,RecvDeltaKB" |
        Out-File $snapshotLog -Encoding UTF8
    # v4.3: clean (unicast) vs noise (broadcast+multicast) byte series, sourced
    # from the NIC's own per-cast counters. CleanCum* is the Iridium-relevant
    # number; NoiseCumRecvMB is the broadcast/multicast that the segment floods.
    "Timestamp,CleanSendKB,CleanRecvKB,NoiseRecvKB,CleanCumSendMB,CleanCumRecvMB,NoiseCumRecvMB" |
        Out-File $unicastLog -Encoding UTF8

    # v4.3: Verify the NIC actually populates the per-cast byte counters. Most
    # physical adapters (e.g. the Intel I219 on the OptiPlex) do; some virtual /
    # emulated NICs leave them at 0. Probe once: if every adapter reports zero
    # unicast AND zero broadcast/multicast while it HAS moved bytes, the driver
    # doesn't expose the split, so disable the clean counter (RAW + Category
    # tagging still run). No pktmon, no admin-only tool, no fragile parsing.
    if ($EnableCleanStats) {
        try {
            $probe = Get-InterfaceBytes
            $anyCast = $false; $anyBytes = $false
            foreach ($k in $probe.Keys) {
                $p = $probe[$k]
                if (($p.UniRecv + $p.UniSent + $p.BcastRecv + $p.McastRecv) -gt 0) { $anyCast = $true }
                if (($p.Received + $p.Sent) -gt 0) { $anyBytes = $true }
            }
            if ($anyCast -or -not $anyBytes) {
                $cleanStatsActive = $true
                $prevCast = @{}
                foreach ($k in $probe.Keys) {
                    $p = $probe[$k]
                    $prevCast[$k] = @{ UniS = $p.UniSent; UniR = $p.UniRecv
                                       BcastR = $p.BcastRecv; McastR = $p.McastRecv }
                }
                Write-Host "Clean unicast/broadcast/multicast counter active (Get-NetAdapterStatistics)." -ForegroundColor Green
            } else {
                Write-Host "NIC does not populate per-cast byte counters - clean split disabled." -ForegroundColor Red
                Write-Host "Falling back to the Category column in the connections CSV." -ForegroundColor Red
            }
        } catch {
            Write-Host "WARNING: could not read NIC per-cast counters ($($_.Exception.Message))." -ForegroundColor Red
            $cleanStatsActive = $false
        }
    }

    # Launch the background DNS logger (ETW Event 3006, cache-poll fallback).
    Write-Host "Starting DNS query logger (ETW)..." -ForegroundColor Yellow

    $dnsJob = Start-Job -ArgumentList $dnsQueryLog -ScriptBlock {
        param($dnsLogPath)

        # Prefer the ETW provider; fall back to cache polling if it's missing.
        $useETW = $true
        try { $null = Get-WinEvent -ListProvider 'Microsoft-Windows-DNS-Client' -ErrorAction Stop }
        catch { $useETW = $false }

        if ($useETW) {
            # Poll for new DNS query events since the last check, append each.
            $lastSeen = (Get-Date).AddSeconds(-30)
            while ($true) {
                try {
                    $events = Get-WinEvent -FilterHashtable @{
                    ProviderName = 'Microsoft-Windows-DNS-Client'
                    Id           = 3006
                    StartTime    = $lastSeen
                    } -ErrorAction SilentlyContinue

                    if ($events) {
                    foreach ($e in $events) {
                    $ts    = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    $qname = $e.Properties[0].Value
                    $qtype = $e.Properties[1].Value
                    $epid  = $e.ProcessId
                    $pname = try {
                    (Get-Process -Id $epid -EA SilentlyContinue).ProcessName
                    } catch { "--" }
                    if (-not $pname) { $pname = "--" }
                    $qnameEsc = '"' + ($qname -replace '"','""') + '"'
                    "$ts,$qnameEsc,$qtype,$epid,$pname" |
                    Out-File $dnsLogPath -Append -Encoding UTF8
                    }
                    $lastSeen = (Get-Date)
                    }
                } catch { }
                Start-Sleep -Seconds 10
            }
        } else {
            # Fallback: read the resolver cache and log entries we haven't seen.
            $seen = @{}
            while ($true) {
                try {
                    Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = "$($_.Entry)|$($_.Type)"
                    if (!$seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    "$ts,$($_.Entry),$($_.Type),--,--" |
                    Out-File $dnsLogPath -Append -Encoding UTF8
                    }
                    }
                } catch { }
                Start-Sleep -Seconds 10
            }
        }
    }

    while ($true) {
        $iteration++
        $now = Get-Date
        $ts  = $now.ToString("yyyy-MM-dd HH:mm:ss")

        # A. Interface deltas (ground truth). Clamp negatives caused by NIC
        #    counter resets / wraps / DHCP renewals, and count them.
        $currentIface = Get-InterfaceBytes
        foreach ($ifName in $currentIface.Keys) {
            $cur = $currentIface[$ifName]
            $sendDelta = 0; $recvDelta = 0
            if ($prevIfaceBytes.ContainsKey($ifName)) {
                $prev = $prevIfaceBytes[$ifName]
                $rawSend = $cur.Sent - $prev.Sent
                $rawRecv = $cur.Received - $prev.Received

                if ($rawSend -lt 0 -or $rawRecv -lt 0) {
                    $resetCount++
                    Write-Host "  [counter reset on $ifName at $ts | prevS=$($prev.Sent) curS=$($cur.Sent) prevR=$($prev.Received) curR=$($cur.Received)]" -ForegroundColor DarkYellow
                }
                $sendDelta = [math]::Max([long]0, $rawSend)
                $recvDelta = [math]::Max([long]0, $rawRecv)
            }
            $sendDeltaKB = [math]::Round($sendDelta / 1KB, 2)
            $recvDeltaKB = [math]::Round($recvDelta / 1KB, 2)

            "$ts,$ifName,$($cur.Sent),$($cur.Received),$sendDeltaKB,$recvDeltaKB" |
                Out-File $snapshotLog -Append -Encoding UTF8

            # Accumulate this interface's deltas into the current hour bucket.
            if (!$hourlyBucket.ContainsKey($ifName)) {
                $hourlyBucket[$ifName] = @{ Send = 0; Recv = 0 }
            }
            $hourlyBucket[$ifName].Send += $sendDelta
            $hourlyBucket[$ifName].Recv += $recvDelta
            # v4.2: accumulate RAW (Layer-2, noise-included) totals for report parity.
            $rawTotalSend += $sendDelta
            $rawTotalRecv += $recvDelta
        }
        $prevIfaceSnapshot = $prevIfaceBytes
        $prevIfaceBytes    = $currentIface

        # A2. v4.3 CLEAN vs NOISE split (native NIC per-cast counters). The unicast
        #     bytes are real traffic to/from this rig (the only thing that can cross
        #     Iridium); broadcast + multicast bytes are segment flooding (Proxmox
        #     chatter, ARP, mDNS, LLMNR, SSDP) that the NIC receives at Layer 2 but
        #     that never leaves over a WAN link. No filter, no pktmon - the adapter
        #     itself classifies every frame, so the separation is exact.
        if ($cleanStatsActive) {
            $cleanSndDelta = [long]0; $cleanRcvDelta = [long]0; $noiseRcvDelta = [long]0
            foreach ($ifName in $currentIface.Keys) {
                $c = $currentIface[$ifName]
                if ($prevCast.ContainsKey($ifName)) {
                    $pc = $prevCast[$ifName]
                    $cleanSndDelta += [math]::Max([long]0, $c.UniSent  - $pc.UniS)
                    $cleanRcvDelta += [math]::Max([long]0, $c.UniRecv  - $pc.UniR)
                    $noiseRcvDelta += [math]::Max([long]0, $c.BcastRecv - $pc.BcastR)
                    $noiseRcvDelta += [math]::Max([long]0, $c.McastRecv - $pc.McastR)
                }
                $prevCast[$ifName] = @{ UniS = $c.UniSent; UniR = $c.UniRecv
                                        BcastR = $c.BcastRecv; McastR = $c.McastRecv }
            }
            $cleanTotalSend += $cleanSndDelta
            $cleanTotalRecv += $cleanRcvDelta
            $noiseTotalRecv += $noiseRcvDelta
            $cSendKB  = [math]::Round($cleanSndDelta / 1KB, 2)
            $cRecvKB  = [math]::Round($cleanRcvDelta / 1KB, 2)
            $nRecvKB  = [math]::Round($noiseRcvDelta / 1KB, 2)
            $cCumS    = [math]::Round($cleanTotalSend / 1MB, 3)
            $cCumR    = [math]::Round($cleanTotalRecv / 1MB, 3)
            $nCumR    = [math]::Round($noiseTotalRecv / 1MB, 3)
            "$ts,$cSendKB,$cRecvKB,$nRecvKB,$cCumS,$cCumR,$nCumR" | Out-File $unicastLog -Append -Encoding UTF8
        }

        # B. Per-process I/O deltas. Only log a process when it actually moved
        #    bytes this interval. (No rows on the first pass: no prev to diff.)
        $currentProc = Get-ProcessNetIO
        $procDeltas  = @()
        foreach ($procId in $currentProc.Keys) {
            $cur = $currentProc[$procId]
            $sendDelta = 0; $recvDelta = 0
            if ($prevProcessBytes.ContainsKey($procId)) {
                $prev = $prevProcessBytes[$procId]
                if ($prev.Name -eq $cur.Name) {   # guard against PID reuse
                    $sendDelta = [math]::Max([long]0, $cur.Send - $prev.Send)
                    $recvDelta = [math]::Max([long]0, $cur.Recv - $prev.Recv)
                }
            }
            if ($sendDelta -gt 0 -or $recvDelta -gt 0) {
                "$ts,$procId,$($cur.Name),$($cur.Send),$($cur.Recv),$sendDelta,$recvDelta" |
                    Out-File $processLog -Append -Encoding UTF8
                $procDeltas += @{ Name=$cur.Name; Send=$sendDelta; Recv=$recvDelta }
            }
        }
        $prevProcessBytes = $currentProc

        # C. Active outbound connections. Resolve each remote IP and log it.
        $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0)" -and $_.State -ne "Listen" }

        $remoteIPs = @{}
        foreach ($conn in $tcpConns) {
            $procName = try {
                (Get-Process -Id $conn.OwningProcess -EA SilentlyContinue).ProcessName
            } catch { "PID_$($conn.OwningProcess)" }
            $resolved = Resolve-Cached $conn.RemoteAddress

            # v4.2: tag the destination so the CSV can be sliced to WAN-only and
            # known noise sources (e.g. Proxmox) can be excluded in one filter.
            $category    = Get-IPCategory $conn.RemoteAddress
            $isNoise     = if ($noiseSet.ContainsKey($conn.RemoteAddress)) { "True" } else { "False" }

            "$ts,$($conn.OwningProcess),$procName,TCP,$($conn.LocalAddress),$($conn.LocalPort),$($conn.RemoteAddress),$($conn.RemotePort),$($conn.State),$resolved,$category,$isNoise" |
                Out-File $connLog -Append -Encoding UTF8

            $remoteIPs[$conn.RemoteAddress] = $resolved
        }

        # D. Hourly rollup: when the clock hour rolls over, flush the bucket.
        if ($now.Hour -ne $lastHour -and $iteration -gt 1) {
            $totalSend = 0; $totalRecv = 0
            foreach ($if in $hourlyBucket.Keys) {
                $totalSend += $hourlyBucket[$if].Send
                $totalRecv += $hourlyBucket[$if].Recv
            }
            $sendMB = [math]::Round($totalSend / 1MB, 3)
            $recvMB = [math]::Round($totalRecv / 1MB, 3)

            "$ts,Hour_$lastHour,$sendMB,$recvMB,N/A,0,$($remoteIPs.Count),--" |
                Out-File $summaryLog -Append -Encoding UTF8

            $hourlyBucket = @{}
            $lastHour = $now.Hour
        }

        # E. Console dashboard.
        Clear-Host
        $runtime = $now - $startTime
        Write-Host "=== Network Monitor v4.3 | $ts | Runtime: $($runtime.ToString('dd\.hh\:mm\:ss')) | Resets: $resetCount ===" -ForegroundColor Cyan
        Write-Host ""

        # v4.3: RAW (everything) vs CLEAN (unicast) vs NOISE (broadcast+multicast).
        $rawMB   = [math]::Round(($rawTotalSend + $rawTotalRecv) / 1MB, 3)
        $cleanMB = [math]::Round(($cleanTotalSend + $cleanTotalRecv) / 1MB, 3)
        $noiseMB = [math]::Round($noiseTotalRecv / 1MB, 3)
        Write-Host "--- Accumulated since monitor start ---" -ForegroundColor Yellow
        Write-Host ("  RAW   (NIC total, incl. broadcast/multicast): {0,9:N3} MB  [S {1:N3} / R {2:N3}]" -f $rawMB, ($rawTotalSend/1MB), ($rawTotalRecv/1MB)) -ForegroundColor DarkYellow
        if ($cleanStatsActive) {
            Write-Host ("  CLEAN (unicast to/from this rig = WAN-able)  : {0,9:N3} MB  [S {1:N3} / R {2:N3}]" -f $cleanMB, ($cleanTotalSend/1MB), ($cleanTotalRecv/1MB)) -ForegroundColor Green
            Write-Host ("  NOISE (broadcast+multicast, never on WAN)    : {0,9:N3} MB  [R only]" -f $noiseMB) -ForegroundColor DarkGray
        } else {
            Write-Host "  CLEAN split: disabled (filter by Category col in connections CSV)" -ForegroundColor DarkGray
        }
        Write-Host ""

        # Cumulative interface totals since boot.
        Write-Host "--- Interface Traffic (cumulative since boot) ---" -ForegroundColor Yellow
        foreach ($ifName in $currentIface.Keys) {
            $sentBytes = $currentIface[$ifName].Sent
            $recvBytes = $currentIface[$ifName].Received
            $sentDisplay = if ($sentBytes -ge 1MB) { "{0,10:N2} MB" -f ($sentBytes / 1MB) }
                    else                    { "{0,10:N2} KB" -f ($sentBytes / 1KB) }
            $recvDisplay = if ($recvBytes -ge 1MB) { "{0,10:N2} MB" -f ($recvBytes / 1MB) }
                    else                    { "{0,10:N2} KB" -f ($recvBytes / 1KB) }
            Write-Host ("  {0,-25} Sent: {1}  |  Recv: {2}" -f $ifName, $sentDisplay, $recvDisplay)
        }
        Write-Host ""

        # Per-interface delta over the last interval.
        Write-Host "--- Interface Delta (last ${IntervalSeconds}s) ---" -ForegroundColor Yellow
        foreach ($ifName in $currentIface.Keys) {
            $sDelta = 0; $rDelta = 0
            if ($prevIfaceSnapshot.ContainsKey($ifName)) {
                $sDelta = [math]::Max([long]0, $currentIface[$ifName].Sent     - $prevIfaceSnapshot[$ifName].Sent)
                $rDelta = [math]::Max([long]0, $currentIface[$ifName].Received - $prevIfaceSnapshot[$ifName].Received)
            }
            $sDeltaDisplay = if ($sDelta -ge 1MB) { "{0,10:N2} MB" -f ($sDelta / 1MB) }
                    elseif ($sDelta -ge 1KB) { "{0,10:N2} KB" -f ($sDelta / 1KB) }
                    else { "{0,10} B " -f $sDelta }
            $rDeltaDisplay = if ($rDelta -ge 1MB) { "{0,10:N2} MB" -f ($rDelta / 1MB) }
                    elseif ($rDelta -ge 1KB) { "{0,10:N2} KB" -f ($rDelta / 1KB) }
                    else { "{0,10} B " -f $rDelta }
            Write-Host ("  {0,-25} Sent: {1}  |  Recv: {2}" -f $ifName, $sDeltaDisplay, $rDeltaDisplay)
        }
        Write-Host ""

        # Top processes by I/O delta this interval (total I/O, not net-only).
        Write-Host "--- Top Processes by IO delta this interval (NOT net-only) ---" -ForegroundColor Yellow
        $procDeltas | Sort-Object { $_.Send + $_.Recv } -Descending | Select-Object -First 10 | ForEach-Object {
            $totalKB = [math]::Round(($_.Send + $_.Recv) / 1KB, 1)
            $color = if ($_.Name -match "TIPS|tips") { "Green" }
                    elseif ($_.Name -match "svchost|System|MoUso|Smart|Defender|msedge|LockApp|Widgets|backgroundTaskHost") { "Red" }
                    else { "White" }
            Write-Host ("  {0,-30} W: {1,8} KB  R: {2,8} KB  Total: {3,8} KB" -f `
                $_.Name, [math]::Round($_.Send/1KB,1), [math]::Round($_.Recv/1KB,1), $totalKB) -ForegroundColor $color
        }
        Write-Host ""

        # Active outbound connections grouped by remote IP.
        Write-Host "--- Active Outbound Connections ($($tcpConns.Count) TCP) ---" -ForegroundColor Yellow
        $grouped = $tcpConns | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 15
        Write-Host ("{0,-40} {1,-40} {2,-6} {3}" -f "Remote IP", "Resolved Name", "Conns", "Processes") -ForegroundColor DarkGray
        foreach ($g in $grouped) {
            $ip = $g.Name
            $dns = if ($remoteIPs[$ip]) { $remoteIPs[$ip] } else { "" }
            if ($dns.Length -gt 38) { $dns = $dns.Substring(0,36) + ".." }
            $procs = ($g.Group | ForEach-Object {
                try { (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName } catch { "?" }
            } | Sort-Object -Unique) -join ", "

            $color = if ($procs -match "TIPS|tips|tailscale") { "Green" }
                    elseif ($dns -match "microsoft\.com|msedge|windows|bing|msn|akamai") { "Red" }
                    else { "White" }
            Write-Host ("{0,-40} {1,-40} {2,-6} {3}" -f $ip, $dns, $g.Count, $procs) -ForegroundColor $color
        }

        Write-Host ""
        Write-Host "GREEN = TIPS/Tailscale  |  RED = Microsoft/Akamai  |  WHITE = Other" -ForegroundColor DarkGray
        Write-Host "Logs: $LogPath" -ForegroundColor DarkGray

        # F. Log size warning (never auto-deletes).
        $totalLogSize = (Get-ChildItem $LogPath -File | Measure-Object -Property Length -Sum).Sum / 1MB
        if ($totalLogSize -gt $MaxLogSizeMB) {
            Write-Host ""
            Write-Host "WARNING: Log size $([math]::Round($totalLogSize,1))MB exceeded cap of ${MaxLogSizeMB}MB." -ForegroundColor Red
            Write-Host "         Stop monitor and archive logs manually - auto-deletion disabled." -ForegroundColor Red
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}
finally {
    # Always tear down the DNS background job, then emit the final report.
    if ($dnsJob) {
        Stop-Job   $dnsJob -ErrorAction SilentlyContinue
        Remove-Job $dnsJob -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "====" -ForegroundColor Cyan
    Write-Host "  MONITOR STOPPED - GENERATING FINAL REPORT" -ForegroundColor Cyan
    Write-Host "====" -ForegroundColor Cyan

    $reportFile = Join-Path $LogPath "FINAL_REPORT_$dateStamp.txt"
    $runtime    = (Get-Date) - $startTime
    $hours      = [math]::Max(0.0001, $runtime.TotalHours)

    # v4.3: compute RAW / CLEAN(unicast) / NOISE(bcast+mcast) totals + 30-day
    # projections (formula: MB/hr * 24 * 30) so the broadcast inflation is
    # quantified directly from the NIC's own per-cast counters.
    $rawTotMB    = [math]::Round(($rawTotalSend   + $rawTotalRecv)   / 1MB, 3)
    $cleanTotMB  = [math]::Round(($cleanTotalSend + $cleanTotalRecv) / 1MB, 3)
    $noiseTotMB  = [math]::Round($noiseTotalRecv / 1MB, 3)
    $rawProj     = [math]::Round(($rawTotMB   / $hours) * 24 * 30, 1)
    $cleanProj   = [math]::Round(($cleanTotMB / $hours) * 24 * 30, 1)
    $noiseProj   = [math]::Round(($noiseTotMB / $hours) * 24 * 30, 1)
    $noisePct    = if ($rawTotMB -gt 0) { [math]::Round(($noiseTotMB / $rawTotMB) * 100, 1) } else { 0 }
    $verdict     = if ($cleanProj -lt 100) { "WITHIN the <100 MB/month Iridium budget" }
                   else                    { "OVER the <100 MB/month budget - investigate WAN rows" }

    if ($cleanStatsActive) {
        $cleanBlock = @"
CLEAN UNICAST (real to/from-this-rig traffic = the only thing Iridium carries):
  Clean total:          $cleanTotMB MB  (Send $([math]::Round($cleanTotalSend/1MB,3)) / Recv $([math]::Round($cleanTotalRecv/1MB,3)))
  >> CLEAN 30-day projection:  $cleanProj MB/month   <-- TRUST THIS FOR IRIDIUM
  Verdict:              $verdict

SUBNET NOISE (broadcast + multicast received at the NIC - NEVER leaves on WAN):
  Noise total:          $noiseTotMB MB received  ($noisePct% of the raw NIC total)
  Noise 30-day projection: $noiseProj MB/month  (e.g. Proxmox/ARP/mDNS - IGNORE for Iridium)
  Series file:          $unicastLog  (CleanCum* vs NoiseCumRecvMB columns)
"@
    } else {
        $cleanBlock = @"
CLEAN/NOISE SPLIT: DISABLED for this run (NIC did not expose per-cast counters).
  Use the connections CSV instead: keep rows where Category=WAN and
  NoiseSource=False to isolate true WAN traffic from LAN/broadcast/multicast.
"@
    }

    $report = @"
Network Monitor v4.3 - Final Report
Generated: $(Get-Date)
Runtime:   $($runtime.ToString('dd\.hh\:mm\:ss'))  ($([math]::Round($hours,2)) hours)
Counter resets observed: $resetCount
====

TRAFFIC SUMMARY (RAW vs CLEAN vs NOISE)
  RAW NIC total (Layer-2, INCLUDES broadcast/multicast noise):
    $rawTotMB MB  (Send $([math]::Round($rawTotalSend/1MB,3)) / Recv $([math]::Round($rawTotalRecv/1MB,3)))
    RAW 30-day projection: $rawProj MB/month  (inflated by subnet noise - do NOT use for Iridium)

$cleanBlock
====

LOG FILES:
  Connections:    $connLog   (v4.3: + Category[WAN/LAN/Multicast/Broadcast/Listen] & NoiseSource)
  Process IO:     $processLog       (NOTE: total I/O, not net-only)
  DNS Queries:    $dnsQueryLog      (ETW: Microsoft-Windows-DNS-Client/3006)
  Interface Data: $snapshotLog      (GROUND TRUTH - RAW NIC byte counters)
  Hourly Summary: $summaryLog       (deltas clamped to >=0)
  Clean/Noise:    $unicastLog       (v4.3: unicast vs broadcast+multicast byte series)

ANALYSIS WORKFLOW:
  1. wan_unicast CSV          -> CleanCumSendMB/CleanCumRecvMB = true WAN bytes;
                    NoiseCumRecvMB = broadcast/multicast you can ignore.
                    CleanCum* is the noise-free series for Iridium planning.
  2. connections CSV          -> filter Category=WAN AND NoiseSource=False for
                    the real off-network destinations. NOTE: Category=Listen
                    rows are idle local sockets (RemoteAddr ::/0.0.0.0), NOT WAN.
  3. interface_snapshots CSV  -> RAW NIC deltas; spikes here that are ABSENT from
                    the CleanCum series = external broadcast bursts (e.g. Proxmox).
  4. dns_queries CSV          -> pivot QueryName, count desc. Anything not
                    TIPS/Tailscale/national.rfitv.army.mil = leak.
  5. process_bytes CSV        -> rank busy procs (relative only - disk + net).

LEAK HUNTING CHECKLIST:
  ( ) CLEAN projection over 100 MB/mo? -> real WAN leak, investigate WAN rows
  ( ) RAW >> CLEAN (big NOISE)?        -> subnet broadcast/multicast; NOT a leak
  ( ) DNS to *.microsoft.com?          -> sinkhole missed an entry
  ( ) DNS to *.akamai*?                -> Edge/Store/CDN slipped through
  ( ) WAN row to msedgewebview2/MsMpEng?-> firewall path rule did not match
  ( ) LockApp connections?             -> firewall block did not take

"@
    $report | Out-File $reportFile -Encoding UTF8
    Write-Host $report
    Write-Host "Report saved: $reportFile" -ForegroundColor Green
}
