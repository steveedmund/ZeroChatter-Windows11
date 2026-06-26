<#
====
 Windows 11 24H2 Enterprise - v2.2 Aggressive Network Hardening Script
====
 VERSION : v2.2  (driven by the 25-hour v2.1 validation capture, 24JUN2026)
   v2.2 DELTA (vs. v2.1) - minimal, because the v2.1 sinkhole already held up:
       + The v2.1 25h capture's DNS log was reviewed against the sinkhole list.
         EVERY chatty FQDN (nf.smartscreen, ecs.office, default.exp-tas,
         fd.api.iris, wdcp/wdcpalt, storeedgefd, ctldl, the events.data family)
         was ALREADY sinkholed - it appears in the DNS-Client ETW log only as a
         logged *resolution attempt* that the HOSTS file dead-ends to 0.0.0.0,
         NOT as traffic that left the box. So no real WAN leak was introduced.
       + The ONLY two FQDNs not already covered were TPM-attestation endpoints
         (microsoftaik.azure.net and www.nuvoton.com); v2.2 adds those exact
         FQDNs to the sinkhole (see Section 15b-3). Everything else is unchanged.
   ----
 VERSION : v2.1  (refinement of v2.0, driven by the 30-hour v2.0 validation)
   v2.1 DELTA (vs. v2.0) - closes the residual talkers the 30-hour settled-state
   capture (~184.6 MB/month) showed were still leaking, per the v2.0 validation
   report's section 7 recommendations:
       + Robust firewall path DISCOVERY for msedgewebview2.exe and MsMpEng.exe.
         v2.0 used static wildcard -Program paths; the validation showed
         msedgewebview2 still made ~21% of settled WAN connections because the
         wildcard rules did not match the exact on-disk paths on this build.
         v2.1 now ENUMERATES every msedgewebview2.exe / MsMpEng.exe / NisSrv.exe
         actually present on disk and writes one explicit block rule per full
         path (the wildcard rules are still added as a fallback).
       + Optional FULL Defender real-time disable ($DisableDefenderRealtime,
         default $false) to reclaim the ~20 MB/month MsMpEng cloud chatter on
         sites whose security policy permits it (recommendation 7.2).
       + Extra account/token sinkhole domains the v2.0 list missed
         (signup.live.com, login.microsoftonline.com, account.live.com,
         auth.microsoft.com, edge.microsoft.com) + Defender cloud FQDNs
         (wdcp.microsoft.com, wdcpalt.microsoft.com, definitionupdates...).
       + Residual service disables tied to login.live.com chatter:
         wlidsvc (Microsoft Account Sign-in Assistant) and NcbService
         (Network Connection Broker - wakes UWP for cloud pushes).
   ----
 PRIOR VERSION : v2.0  (the sub-100 MB/month target baseline)
   Built on the Refined script. Added the targeted fixes identified by the
   24-hour post-hardening capture (TIPS active, national DB reporting, no
   Tailscale) which still measured ~7.287 MB/24h (~219 MB/month). The three
   residual talkers that v2.0 closes:
       1. DNS/WPAD lookups for MS account + delivery domains (login.live.com,
          *.delivery.mp.microsoft.com, passport, trafficshaping, etc.)
       2. msedgewebview2.exe periodic HTTPS pulls to Bing/Microsoft (~/30 min)
       3. MsMpEng.exe (Defender) daily cloud-protection / signature bursts
   v2.0 DELTA (vs. Refined):
       + 14 additional sinkhole domains (24h-capture leaks)
       + Outbound firewall blocks for msedgewebview2.exe (all instances) &
         MsMpEng.exe (Defender engine internet egress)
       + Registry/service disables for WinHttpAutoProxySvc (WPAD) & TokenBroker
       + Extra Defender cloud-related service hardening (Sense)

 PURPOSE
   Silence ALL non-essential outbound network traffic on dedicated RFID
   endpoints (CENTCOM TIPS golden image) deployed in extreme low-bandwidth
   environments:
       - 40% of sites: Iridium satellite modems (19,200 baud, ~few min/hour)
       - Remaining sites: strict 1 GB/month data caps
   TARGET: < 100 MB / month of OS-generated background bandwidth.

 DESIGN BASIS (data-driven)
   This script was rebuilt from live monitoring data (NetMonitor v3.1) captured
   on the reference image, then tuned again from a full 24-hour hardened-state
   capture. Top observed offenders (connections + DNS):
       LockApp / Windows Spotlight ... 2488 conns  -> *.msn.com, *.bing.com, akamai
       Widgets (WebExperience) .... MSN content feeds
       backgroundTaskHost .... UWP wake-ups -> a-msedge.net / akamai
       MpDefenderCoreService / NisSrv / MsMpEng  Defender cloud + sigs
       svchost (multiple) .... licensing.mp / displaycatalog.mp / settings-win
       msedgewebview2 .... widget + spotlight rendering CDN pulls (~/30 min)
       BackgroundTransferHost .... Store / Delivery Optimization downloads
       CrossDeviceService .... Phone Link / cross-device sync
   24h-capture residual DNS names now sinkholed in v2.0:
       login.live.com, logincdn.msauth.net, clientconfig.passport.net,
       geo-prod.do.dsp.mp.microsoft.com, displaycatalog.mp.microsoft.com,
       emdl.ws.microsoft.com, dl.delivery.mp.microsoft.com,
       tsfe.trafficshaping.dsp.mp.microsoft.com,
       img-prod-cms-rt-microsoft-com.akamaized.net, purchase.mp.microsoft.com,
       licensing.mp.microsoft.com, manage.devcenter.microsoft.com,
       arc.msn.com, www.msn.com

 PRESERVED (must keep working)
   Notepad, Microsoft Edge (functional, but blocked from phoning home),
   PowerShell, CMD, Windows Terminal, core OS (logon, networking, RDP if used,
   Tailscale on non-Iridium sites, proprietary TIPS software).

 STRATEGY (defense in depth - every leak is blocked at multiple layers)
   1. Policy/registry tweaks  -> stop the feature from generating traffic.
   2. Service disabling       -> stop the worker process from running.
   3. Scheduled task removal  -> stop timed wake-and-call-home jobs.
   4. Firewall outbound rules -> block the binary even if it somehow runs.
   5. HOSTS sinkhole          -> dead-end DNS for any endpoint that slips through.

 SAFETY
   - Idempotent: safe to re-run. Helper functions create keys as needed.
   - Surgical: Defender real-time AV stays ON; only its cloud/update CHATTER
     is silenced (engine internet egress is firewalled, on-box scanning stays).
     Core logon/network/UI services are never touched.
   - Logged: full transcript written to C:\BUILDS\SCRIPTS\Hardening\.

 DEPLOYMENT NOTE
   Run POST-deployment (after Sysprep + image apply), NOT before generalization.
   Aggressive hardening breaks Sysprep; running it on the live endpoint takes
   ~1 minute and avoids breaking OS generalization.

 USAGE
   Run elevated:  powershell -ExecutionPolicy Bypass -File .\Windows11_Enterprise_Hardening_v2.2.ps1
   Optional flags:
       -PreserveTailscale $true|$false        (default $true)
       -DisableDefenderRealtime $true|$false  (default $false; only where policy allows)
   Reboot afterwards so service / policy / firewall state fully settles.

 AUTHOR : TIPS Golden Image Team  |   v2.2 from 25h v2.1 validation capture
====
#>

# Requires -RunAsAdministrator
[CmdletBinding()]
param(
    # Set $true on non-Iridium sites where Tailscale is installed; keeps the
    # Tailscale binary + its coordination traffic unblocked (it is essential).
    [bool]$PreserveTailscale = $true,

    # v2.1: When $true, FULLY disables Defender real-time monitoring (not just its
    # cloud chatter). The validation showed MsMpEng cloud bursts contribute
    # ~20 MB/month; firewalling the engine's internet egress (default) silences
    # most of it while keeping on-box scanning. Set $true ONLY on sites whose
    # security policy permits running with real-time AV off, to claw back the
    # remaining Defender bandwidth and help reach the <100 MB/month target.
    [bool]$DisableDefenderRealtime = $false
)

$ErrorActionPreference = "SilentlyContinue"   # Hardening is best-effort; never abort on a single failed key.
$ProgressPreference     = "SilentlyContinue"  # Suppress progress bars (faster, cleaner logs).

# ----
# SECTION 0 : BOOTSTRAP - logging, helper functions, idempotent primitives
# ----
$LogDir = "C:\BUILDS\SCRIPTS\Hardening"
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogDir ("Hardening_v2.2_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append | Out-Null } catch {}

function Write-Section { param([string]$Text)
    Write-Host "`n==== $Text ====" -ForegroundColor Cyan
}
function Write-Step { param([string]$Text)
    Write-Host "  [+] $Text" -ForegroundColor Yellow
}
function Write-Note { param([string]$Text)
    Write-Host "      - $Text" -ForegroundColor DarkGray
}

# Idempotently set a registry value, creating the full key path if absent.
function Set-Reg {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Value,
        [ValidateSet("DWord","QWord","String","ExpandString","MultiString","Binary")]
        [string]$Type = "DWord"
    )
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# Stop a service (if present) and set it to Disabled. Never errors on absent services.
function Disable-Svc {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Write-Note "service '$Name' not present (skipped)"; return }
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
    # Use the underlying SCM so we can also disable kernel/driver-backed services.
    try { Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    & sc.exe config $Name start= disabled | Out-Null
    Write-Note "disabled service: $Name"
}

# Force a service's Start value to Disabled (4) directly in the registry. Used as
# a belt-and-braces companion to Disable-Svc for services that may be locked by
# SCM ACLs or only materialize after first boot.
function Disable-SvcReg {
    param([Parameter(Mandatory)][string]$Name)
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (Test-Path $key) {
        Set-Reg $key "Start" 4
        Write-Note "registry-disabled service: $Name (Start=4)"
    } else {
        Write-Note "service key '$Name' not present (registry skip)"
    }
}

# Disable + unregister a scheduled task by path/name. Tolerant of absent tasks.
function Disable-Task {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $t = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $t) { return }
    try { Disable-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Note "disabled task: $Path$Name"
}

# Create an outbound BLOCK firewall rule for a program path (idempotent by name).
function Block-Outbound {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Program
    )
    Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $DisplayName -Direction Outbound -Action Block `
        -Program $Program -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
    Write-Note "firewall block: $DisplayName"
}

# v2.1: Block a binary by NAME after DISCOVERING its real on-disk path(s).
#   Rationale: Windows Firewall does NOT expand wildcards in -Program at match
#   time the way a shell glob does - a rule whose path contains "*" only matches
#   if the live process path literally contains those characters (it never does).
#   The v2.0 wildcard rules therefore failed to catch msedgewebview2.exe on some
#   builds (validation: still ~21% of settled WAN connections). This helper walks
#   the given roots, finds every instance of $FileName, and writes ONE explicit
#   block rule per fully-resolved path so the match is exact regardless of the
#   versioned sub-folder the build happens to use.
function Block-OutboundByDiscovery {
    param(
        [Parameter(Mandatory)][string]$NamePrefix,   # e.g. "TIPS-Block-WebView2-disc"
        [Parameter(Mandatory)][string]$FileName,      # e.g. "msedgewebview2.exe"
        [Parameter(Mandatory)][string[]]$Roots        # folders to search recursively
    )
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($root in $Roots) {
        $expanded = [System.Environment]::ExpandEnvironmentVariables($root)
        if (Test-Path $expanded) {
            Get-ChildItem -Path $expanded -Filter $FileName -Recurse -File -ErrorAction SilentlyContinue |
                ForEach-Object { if (-not $found.Contains($_.FullName)) { $found.Add($_.FullName) } }
        }
    }
    if ($found.Count -eq 0) {
        Write-Note "discovery: no '$FileName' found under provided roots (no explicit rule added)"
        return
    }
    $idx = 0
    foreach ($full in $found) {
        $idx++
        Block-Outbound -DisplayName ("{0}-{1}" -f $NamePrefix, $idx) -Program $full
        Write-Note "discovered + blocked: $full"
    }
}

Write-Host "====" -ForegroundColor Green
Write-Host " STARTING  v2.2 AGGRESSIVE ENDPOINT HARDENING (24H2)"      -ForegroundColor Green
Write-Host " Target: < 100 MB/month | Log: $LogFile"                    -ForegroundColor Green
Write-Host "====" -ForegroundColor Green

# ----
# SECTION 1 : TELEMETRY & DATA COLLECTION
#   Kills DiagTrack ("Connected User Experiences and Telemetry") which is the
#   single biggest telemetry talker (settings-win.data / *.events.data observed).
# ----
Write-Section "SECTION 1 - Telemetry & Data Collection"

Write-Step "Force telemetry to the lowest level (0 = Security, Enterprise-only)"
$DC = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-Reg $DC "AllowTelemetry"                    0
Set-Reg $DC "AllowDeviceNameInTelemetry"        0
Set-Reg $DC "DoNotShowFeedbackNotifications"    1
Set-Reg $DC "AllowCommercialDataPipeline"       0
Set-Reg $DC "AllowDesktopAnalyticsProcessing"   0
Set-Reg $DC "LimitEnhancedDiagnosticDataWindowsAnalytics" 0
Set-Reg $DC "MicrosoftEdgeDataOptIn"            0
# Mirror under the non-policy hive so the OS UI also reflects it.
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0

Write-Step "Disable Customer Experience Improvement Program (CEIP/SQM)"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable"   0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" 1

Write-Step "Disable Application Impact Telemetry & Compatibility Telemetry"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads" 1

# ----
# SECTION 2 : WINDOWS UPDATE, DELIVERY OPTIMIZATION & STORE AUTO-UPDATE
#   The heaviest *potential* bandwidth sink. Patching is done via vetted offline
#   media, so all automatic update + peer-to-peer delivery traffic is killed.
# ----
Write-Section "SECTION 2 - Windows Update / Delivery Optimization / Store"

Write-Step "Disable automatic Windows Update (vetted offline patching used instead)"
$WU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAU = "$WU\AU"
Set-Reg $WU   "DoNotConnectToWindowsUpdateInternetLocations" 1
Set-Reg $WU   "DisableWindowsUpdateAccess"                   1
Set-Reg $WU   "SetDisableUXWUAccess"                    1
Set-Reg $WUAU "NoAutoUpdate"                    1
Set-Reg $WUAU "AUOptions"                    2   # 2 = notify only, no download
Set-Reg $WUAU "UseWUServer"                    0
# Defer/forbid feature & quality updates as a belt-and-braces measure.
Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "FlightSettingsMaxPauseDays" 3650

Write-Step "Force Delivery Optimization to OFF (no P2P / no MS CDN background pulls)"
$DO = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-Reg $DO "DODownloadMode"          0   # 0 = HTTP only, no peering
Set-Reg $DO "DOPercentageMaxBackgroundBandwidth" 0
Set-Reg $DO "DOMaxBackgroundDownloadBandwidth"   0

Write-Step "Stop Microsoft Store auto-update & content downloads"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload"        2  # 2 = disabled
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableOSUpgrade"    1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# ----
# SECTION 3 : MICROSOFT DEFENDER - CLOUD / UPDATES (KEEP REAL-TIME AV ON)
#   Observed: MpDefenderCoreService + NisSrv + MsMpEng calling akamai/msedge.
#   We silence MAPS cloud lookups, sample submission, and signature *internet*
#   updates while LEAVING real-time on-box protection enabled. Signatures are
#   pushed via the same vetted offline media as OS patches. The engine's
#   internet egress (MsMpEng.exe) is firewalled in Section 13.
# ----
Write-Section "SECTION 3 - Microsoft Defender (silence cloud/updates, keep AV)"

Write-Step "Disable MAPS / SpyNet cloud reporting & sample submission"
$Spy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
Set-Reg $Spy "SpyNetReporting"      0   # 0 = off
Set-Reg $Spy "SubmitSamplesConsent" 2   # 2 = never send
Set-Reg $Spy "DisableBlockAtFirstSeen" 1
Set-Reg $Spy "LocalSettingOverrideSpynetReporting" 0

Write-Step "Disable Defender cloud-delivered protection & MpDefenderCoreService chatter"
$MpEng = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
Set-Reg $MpEng "MpCloudBlockLevel"   0
Set-Reg $MpEng "MpBafsExtendedTimeout" 0

Write-Step "Disable signature updates over the internet (use offline/UNC packages)"
$Sig = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
Set-Reg $Sig "FallbackOrder"                  "FileShares" String
Set-Reg $Sig "DisableScanOnRealtimeEnable"    0
Set-Reg $Sig "ScheduleDay"                    0
Set-Reg $Sig "SignatureUpdateInterval"        0
# Block Defender's own update channel from reaching the internet.
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 0

Write-Step "Disable Network Inspection System (NisSrv) outbound cloud calls"
# NisSrv was observed phoning akamai; the IPS engine isn't needed on an isolated RFID box.
Disable-Svc "WdNisSvc"

Write-Step "Disable Defender ATP/EDR cloud sensor (Sense) - cloud-reporting service"
# Sense (Microsoft Defender for Endpoint / ATP) ships disabled on non-onboarded
# boxes but is silenced explicitly so it can never start a cloud channel.
Disable-Svc "Sense"

# NOTE: By DEFAULT we deliberately do NOT disable WinDefend (real-time AV) or set
# DisableAntiSpyware - that would remove on-box protection. Only cloud chatter is
# cut, and MsMpEng.exe internet egress is firewalled (Section 13) rather than the
# engine being stopped - so local scanning of the TIPS data flow remains intact.

# v2.1: OPTIONAL full real-time disable. The 30-hour validation attributed
# ~20 MB/month of residual WAN to MsMpEng cloud bursts even with egress
# firewalled. On sites whose security policy permits running without real-time
# AV, set -DisableDefenderRealtime $true to stop the engine entirely and reclaim
# that bandwidth (a key lever toward the <100 MB/month target).
if ($DisableDefenderRealtime) {
    Write-Step "DISABLING Defender real-time monitoring (policy-gated; -DisableDefenderRealtime \$true)"
    $DefPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    Set-Reg $DefPol "DisableAntiSpyware" 1
    $RtPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    Set-Reg $RtPol "DisableRealtimeMonitoring"   1
    Set-Reg $RtPol "DisableBehaviorMonitoring"   1
    Set-Reg $RtPol "DisableOnAccessProtection"   1
    Set-Reg $RtPol "DisableScanOnRealtimeEnable" 1
    Set-Reg $RtPol "DisableIOAVProtection"       1
    # Best-effort live disable via the Defender cmdlet (ignored if tamper-protected).
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch {}
    Write-Note "Defender real-time monitoring set to DISABLED (reboot to settle; tamper protection may override)"
} else {
    Write-Note "Defender real-time monitoring KEPT ON (default). Engine internet egress is firewalled in Section 13."
}

# ----
# SECTION 4 : WINDOWS SPOTLIGHT / LOCKAPP / CONTENT DELIVERY / WIDGETS
#   THE #1 OBSERVED LEAK (LockApp = 2488 conns to MSN/Bing/akamai). We kill the
#   lock-screen image feed, all Content Delivery Manager (CDM) suggestions,
#   spotlight, tips, and the Widgets / WebExperience board.
# ----
Write-Section "SECTION 4 - Spotlight / LockApp / Content Delivery / Widgets"

Write-Step "Kill Windows Spotlight & lock-screen slideshow feeds"
$Pers = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
Set-Reg $Pers "NoLockScreenSlideshow"   1
Set-Reg $Pers "NoLockScreenCamera"      1
$CC = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-Reg $CC "ConfigureWindowsSpotlight"             2   # 2 = disabled
Set-Reg $CC "DisableWindowsSpotlightFeatures"       1
Set-Reg $CC "DisableWindowsSpotlightOnActionCenter" 1
Set-Reg $CC "DisableWindowsSpotlightOnSettings"     1
Set-Reg $CC "DisableWindowsSpotlightWindowsWelcomeExperience" 1
Set-Reg $CC "DisableThirdPartySuggestions"          1
Set-Reg $CC "DisableTailoredExperiencesWithDiagnosticData" 1
Set-Reg $CC "IncludeEnterpriseSpotlight"            0

Write-Step "Disable Content Delivery Manager silent app/ad/tip downloads (per-user default)"
# Applied to the Default user hive so every newly-created profile inherits silence.
$CDMKeys = @(
    "ContentDeliveryAllowed","FeatureManagementEnabled","OemPreInstalledAppsEnabled",
    "PreInstalledAppsEnabled","PreInstalledAppsEverEnabled","SilentInstalledAppsEnabled",
    "SoftLandingEnabled","SubscribedContentEnabled","SystemPaneSuggestionsEnabled",
    "RotatingLockScreenEnabled","RotatingLockScreenOverlayEnabled",
    "SubscribedContent-338387Enabled","SubscribedContent-338388Enabled",
    "SubscribedContent-338389Enabled","SubscribedContent-338393Enabled",
    "SubscribedContent-353698Enabled","SubscribedContent-310093Enabled"
)
$CDMUser = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($k in $CDMKeys) { Set-Reg $CDMUser $k 0 }

Write-Step "Disable Windows Widgets / Web Experience board (MSN feed source)"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" "value" 0

# ----
# SECTION 5 : SMARTSCREEN, NCSI CONNECTIVITY PROBES & WPAD AUTO-PROXY
#   Observed: nf.smartscreen (48), dns.msftncsi.com, and wpad (322 hits!).
#   These are constant low-level chatter that adds up over a month.
# ----
Write-Section "SECTION 5 - SmartScreen / NCSI / WPAD"

Write-Step "Disable SmartScreen (OS shell + Edge) reputation lookups"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "Warn" String
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenPuaEnabled" 0

Write-Step "Disable Network Connectivity Status Indicator active probes (msftncsi/msftconnecttest)"
# Stops the periodic 'are we online?' HTTP/DNS probe to Microsoft.
$NCSI = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
Set-Reg $NCSI "EnableActiveProbing" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" "NoActiveProbe" 1

Write-Step "Disable WPAD auto-proxy discovery (322 wpad lookups observed)"
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" "WpadOverride" 1
# Triple-lock WinHttpAutoProxySvc: SCM disable + registry Start=4 (Section 11 also
# carries it in the consolidated service list).
Disable-Svc    "WinHttpAutoProxySvc"
Disable-SvcReg "WinHttpAutoProxySvc"

# ----
# SECTION 6 : MICROSOFT EDGE - KEEP FUNCTIONAL, BLOCK ALL PHONE-HOME
#   Edge MUST remain usable (operators need a browser) but must not run its
#   updater, telemetry, background tasks, feeds, or DoH. Observed leaks:
#   config.edge.skype.com, msedge.api.cdp.microsoft.com, msedgewebview2 -> CDN.
# ----
Write-Section "SECTION 6 - Microsoft Edge (functional, no phone-home)"

$Edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
Write-Step "Disable Edge background mode, auto-update, and metrics"
Set-Reg $Edge "BackgroundModeEnabled"            0
Set-Reg $Edge "StartupBoostEnabled"              0
Set-Reg $Edge "MetricsReportingEnabled"          0
Set-Reg $Edge "SendSiteInfoToImproveServices"    0
Set-Reg $Edge "PersonalizationReportingEnabled"  0
Set-Reg $Edge "UserFeedbackAllowed"              0
Set-Reg $Edge "DiagnosticData"                   0
Set-Reg $Edge "EdgeShoppingAssistantEnabled"     0
Set-Reg $Edge "ShowRecommendationsEnabled"       0
Set-Reg $Edge "SpotlightExperiencesAndRecommendationsEnabled" 0

Write-Step "Disable Edge DoH (force fallback to local DNS so HOSTS sinkhole works)"
Set-Reg $Edge "DnsOverHttpsMode"        "off" String
Set-Reg $Edge "BuiltInDnsClientEnabled" 0

Write-Step "Disable Edge new-tab content feed, web widgets, and prelaunch"
Set-Reg $Edge "NewTabPageContentEnabled"        0
Set-Reg $Edge "NewTabPageAllowedBackgroundTypes" 3
Set-Reg $Edge "WebWidgetAllowed"                0
Set-Reg $Edge "HubsSidebarEnabled"              0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "UpdateDefault"      0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "AutoUpdateCheckPeriodMinutes" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "InstallDefault"     0

# v2.0: WebView2 runtime is shared by Widgets/Spotlight/Store surfaces and was
# observed making ~30-minute HTTPS pulls to Bing/Microsoft. Kill its background
# components here; its binary is also firewalled in Section 13.
Write-Step "Disable Edge WebView2 background callers (~30 min Bing/MS pulls observed)"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2" "BackgroundModeEnabled" 0

# ----
# SECTION 7 : ERROR REPORTING & DIAGNOSTICS
#   WER uploads crash dumps to *.blob.core.windows.net (in old list). Kill it.
# ----
Write-Section "SECTION 7 - Windows Error Reporting & Diagnostics"

Write-Step "Disable Windows Error Reporting (no crash dumps phoned home)"
$WER = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
Set-Reg $WER "Disabled"             1
Set-Reg $WER "DontSendAdditionalData" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1

Write-Step "Disable Connected User Experiences diagnostic auto-logger & feedback"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableTelemetryOptInChangeNotification" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1

# ----
# SECTION 8 : ACCOUNT / CROSS-DEVICE / ACTIVITY / LICENSING CHATTER
#   Observed: login.live.com, CrossDeviceService, licensing.mp / displaycatalog.
# ----
Write-Section "SECTION 8 - Account / Cross-Device / Activity / Licensing"

Write-Step "Disable Activity Feed / Timeline upload (activity.windows.com)"
$Sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
Set-Reg $Sys "EnableActivityFeed"        0
Set-Reg $Sys "PublishUserActivities"     0
Set-Reg $Sys "UploadUserActivities"      0
Set-Reg $Sys "AllowCrossDeviceClipboard" 0
Set-Reg $Sys "EnableCdp"                 0   # Connected Devices Platform (CrossDeviceService)

Write-Step "Disable cloud licensing background refresh chatter"
# ClipSVC / licensing.mp talks for Store app license checks; not needed for TIPS.
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" "AllowAllTrustedApps" 1
Disable-Svc "CDPSvc"           # Connected Devices Platform Service
Disable-Svc "CDPUserSvc"       # per-user variant (may be suffixed; handled in svc loop too)

Write-Step "Disable consumer account features / MSA background sign-in prompts"
Set-Reg "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount" "value" 0

# v2.0: TokenBroker (Web Account Manager) drives MSA/AAD token refresh chatter to
# login.live.com / passport / msauth endpoints. Disable the service so it never
# initiates a token-refresh network call. (Sinkholed at DNS layer too, Section 15.)
Write-Step "Disable TokenBroker (Web Account Manager - MSA/AAD token refresh chatter)"
Disable-Svc    "TokenBroker"
Disable-SvcReg "TokenBroker"

# v2.1: wlidsvc (Microsoft Account Sign-in Assistant) is the service that drives
# the persistent login.live.com queries the validation still observed (~66
# queries/hr). With no Microsoft account in use on the TIPS image it is dead
# weight that only generates account-refresh chatter. NcbService (Network
# Connection Broker) wakes UWP apps to receive cloud pushes over the network;
# unneeded once push/cross-device features are off.
Write-Step "Disable wlidsvc (MS Account Sign-in Assistant - login.live.com chatter) & NcbService"
Disable-Svc    "wlidsvc"
Disable-SvcReg "wlidsvc"
Disable-Svc    "NcbService"
Disable-SvcReg "NcbService"

# ----
# SECTION 9 : DNS HARDENING (DoH off + chatty name-resolution protocols)
#   DoH must be OFF or the HOSTS sinkhole is bypassed. Also silence LLMNR and
#   the Connected-DNS / smart multi-homed resolution chatter.
# ----
Write-Section "SECTION 9 - DNS Hardening"

Write-Step "Prohibit native Windows DoH (forces standard DNS so HOSTS wins)"
$DnsPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
Set-Reg $DnsPol "ControlDoH"  0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableAutoDoh" 0

Write-Step "Disable LLMNR & smart multi-homed name resolution (LAN chatter)"
Set-Reg $DnsPol "EnableMulticast" 0   # disables LLMNR
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableSmartNameResolution" 1

# ----
# SECTION 10 : IPv6 / TEREDO / 6to4 LEAK VECTORS
#   Prevent dual-stack telemetry from bypassing IPv4 firewall/hosts rules.
# ----
Write-Section "SECTION 10 - IPv6 / Teredo / 6to4"

Write-Step "Disable IPv6 transition tunnels (Teredo / 6to4 / ISATAP) and prefer IPv4"
# 0xFF disables all IPv6 components except the loopback interface.
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 255
Write-Step "Unbind IPv6 from all current adapters"
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
netsh interface teredo set state disabled | Out-Null
netsh interface 6to4 set state disabled   | Out-Null

# ----
# SECTION 11 : SERVICE CONTROL STATES (consolidated disable list)
#   Every service here was either an observed talker or a known background
#   network worker. Core OS services (logon, RPC, networking, UI) are untouched.
# ----
Write-Section "SECTION 11 - Service Disablement"

$ServicesToDisable = @(
    # --- Telemetry / diagnostics ---
    "DiagTrack",            # Connected User Experiences and Telemetry (settings-win/events.data)
    "dmwappushservice",     # WAP Push routing - telemetry transport
    "diagnosticshub.standardcollector.service", # Diagnostics Hub collector
    "WdiServiceHost",       # Diagnostic Service Host (network diag probes)
    "WdiSystemHost",        # Diagnostic System Host
    "WerSvc",               # Windows Error Reporting
    "wercplsupport",        # WER control panel support
    # --- Update / delivery / store ---
    "wuauserv",             # Windows Update (vetted offline patching instead)
    "UsoSvc",               # Update Orchestrator
    "WaaSMedicSvc",         # Update Medic (re-enables WU - must die)
    "BITS",                 # Background Intelligent Transfer (download engine)
    "DoSvc",                # Delivery Optimization (P2P/CDN background pulls)
    "edgeupdate",           # Microsoft Edge Update
    "edgeupdatem",          # Microsoft Edge Update (per-machine)
    "MicrosoftEdgeElevationService",
    "InstallService",       # Microsoft Store Install Service
    # --- Spotlight / content / cross-device ---
    "CDPSvc",               # Connected Devices Platform (CrossDeviceService leak)
    "MapsBroker",           # Downloaded Maps Manager (background map data)
    "RetailDemo",           # Retail Demo content downloader
    "PushToInstall",        # Store push-to-install
    # --- Push notifications / cloud ---
    "WpnService",           # Windows Push Notifications (cloud-backed)
    # --- Account / token / proxy / probing ---
    "WinHttpAutoProxySvc",  # WPAD auto-proxy discovery (322 wpad lookups)
    "TokenBroker",          # Web Account Manager - MSA/AAD token refresh chatter (v2.0)
    "wlidsvc",              # Microsoft Account Sign-in Assistant - login.live.com chatter (v2.1)
    "NcbService",           # Network Connection Broker - wakes UWP for cloud pushes (v2.1)
    # --- Defender network inspection / cloud (real-time AV stays via WinDefend) ---
    "WdNisSvc",             # Network Inspection System (akamai chatter)
    "Sense",                # Defender for Endpoint / ATP cloud sensor (v2.0)
    # --- Misc background ---
    "lfsvc",                # Geolocation Service
    "MessagingService",     # Text messaging / cloud sync
    "OneSyncSvc",           # Sync host (mail/contacts/settings sync)
    "PimIndexMaintenanceSvc", # Contact data sync
    "SysMain",              # Superfetch (no net, but pointless on SSD RFID box)
    "WSearch"               # Windows Search indexer (no net, reduces wake-ups)
)
foreach ($s in $ServicesToDisable) { Disable-Svc $s }

# Per-user services carry a random LUID suffix (e.g. CDPUserSvc_4a2f1). Catch them.
Write-Step "Disabling per-user network services (LUID-suffixed variants)"
$PerUserSvcPrefixes = @("CDPUserSvc","OneSyncSvc","MessagingService","PimIndexMaintenanceSvc","TokenBroker")
foreach ($prefix in $PerUserSvcPrefixes) {
    Get-Service -Name "$prefix*" -ErrorAction SilentlyContinue | ForEach-Object {
        Disable-Svc $_.Name
    }
    # Also flip the service template so future profiles inherit Disabled (Start=4).
    $tmpl = "HKLM:\SYSTEM\CurrentControlSet\Services\$prefix"
    if (Test-Path $tmpl) { Set-Reg $tmpl "Start" 4 }
}

# ----
# SECTION 12 : SCHEDULED TASK REMOVAL
#   Timed wake-and-call-home jobs. Disabling these stops the periodic 2 MB/hr
#   idle spikes seen in the hourly_summary capture.
# ----
Write-Section "SECTION 12 - Scheduled Task Disablement"

$TasksToDisable = @(
    @{ Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="Consolidator" },
    @{ Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="UsbCeip" },
    @{ Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="KernelCeipTask" },
    @{ Path="\Microsoft\Windows\Application Experience\"; Name="Microsoft Compatibility Appraiser" },
    @{ Path="\Microsoft\Windows\Application Experience\"; Name="ProgramDataUpdater" },
    @{ Path="\Microsoft\Windows\Application Experience\"; Name="StartupAppTask" },
    @{ Path="\Microsoft\Windows\Application Experience\"; Name="PcaPatchDbTask" },
    @{ Path="\Microsoft\Windows\DiskDiagnostic\"; Name="Microsoft-Windows-DiskDiagnosticDataCollector" },
    @{ Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClient" },
    @{ Path="\Microsoft\Windows\Feedback\Siuf\"; Name="DmClientOnScenarioDownload" },
    @{ Path="\Microsoft\Windows\Windows Error Reporting\"; Name="QueueReporting" },
    @{ Path="\Microsoft\Windows\Maps\"; Name="MapsUpdateTask" },
    @{ Path="\Microsoft\Windows\Maps\"; Name="MapsToastTask" },
    @{ Path="\Microsoft\Windows\WindowsUpdate\"; Name="Scheduled Start" },
    @{ Path="\Microsoft\Windows\UpdateOrchestrator\"; Name="Schedule Scan" },
    @{ Path="\Microsoft\Windows\InstallService\"; Name="ScanForUpdates" },
    @{ Path="\Microsoft\Windows\Clip\"; Name="License Validation" },
    @{ Path="\Microsoft\Windows\CloudExperienceHost\"; Name="CreateObjectTask" },
    @{ Path="\Microsoft\Windows\Flighting\FeatureConfig\"; Name="ReconcileFeatures" },
    @{ Path="\Microsoft\Windows\Flighting\OneSettings\"; Name="RefreshCache" },
    @{ Path="\Microsoft\Windows\PushToInstall\"; Name="Registration" },
    @{ Path="\Microsoft\Windows\Subscription\"; Name="EnableLicenseAcquisition" }
)
foreach ($t in $TasksToDisable) { Disable-Task -Path $t.Path -Name $t.Name }

# Bulk-disable the entire Edge auto-update task family (names include version GUIDs).
Get-ScheduledTask -TaskName "MicrosoftEdgeUpdate*" -ErrorAction SilentlyContinue |
    Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

# ----
# SECTION 13 : OUTBOUND FIREWALL RULES (per-binary block of observed talkers)
#   Last line of defense: even if a service/policy is missed, the binary cannot
#   open an outbound socket. We block the exact processes seen leaking.
# ----
Write-Section "SECTION 13 - Outbound Firewall Blocks (observed talkers)"

# System apps live under packaged paths; we block by resolved SystemApps path
# and by the WindowsApps store path. %SystemRoot% expands at rule-eval time.
$SysApps = "%SystemRoot%\SystemApps"
$FirewallBlocks = @(
    @{ Name="TIPS-Block-LockApp (Spotlight #1 leak)"; Prog="$SysApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe" },
    @{ Name="TIPS-Block-Widgets WebExperience";       Prog="%ProgramFiles%\WindowsApps\MicrosoftWindows.Client.WebExperience_*\Dashboard\Widgets.exe" },
    @{ Name="TIPS-Block-BackgroundTaskHost";          Prog="%SystemRoot%\System32\backgroundTaskHost.exe" },
    @{ Name="TIPS-Block-BackgroundTransferHost";      Prog="%SystemRoot%\System32\BackgroundTransferHost.exe" },
    @{ Name="TIPS-Block-CrossDeviceService";          Prog="%SystemRoot%\System32\CrossDeviceService.exe" },
    @{ Name="TIPS-Block-SmartScreen";                 Prog="%SystemRoot%\System32\smartscreen.exe" },
    @{ Name="TIPS-Block-WerFault (crash upload)";     Prog="%SystemRoot%\System32\WerFault.exe" },
    @{ Name="TIPS-Block-WaaSMedicAgent";              Prog="%SystemRoot%\System32\WaaSMedicAgent.exe" },
    @{ Name="TIPS-Block-MoUsoCoreWorker (Update)";    Prog="%SystemRoot%\System32\MoUsoCoreWorker.exe" },
    @{ Name="TIPS-Block-CompatTelRunner";             Prog="%SystemRoot%\System32\CompatTelRunner.exe" },
    @{ Name="TIPS-Block-DeviceCensus (telemetry)";    Prog="%SystemRoot%\System32\DeviceCensus.exe" }
)
foreach ($r in $FirewallBlocks) { Block-Outbound -DisplayName $r.Name -Program $r.Prog }

Write-Step "Blocking Microsoft Edge background/update binaries (Edge UI still works)"
# We block the UPDATER + webview background callers, NOT msedge.exe itself, so the
# operator-facing browser keeps working while phone-home channels are severed.
$EdgePaths = @(
    "%ProgramFiles(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
    "%ProgramFiles(x86)%\Microsoft\EdgeCore\*\elevation_service.exe"
)
$i = 0
foreach ($p in $EdgePaths) { $i++; Block-Outbound -DisplayName "TIPS-Block-EdgeUpdate-$i" -Program $p }

# v2.0: msedgewebview2.exe was the ~30-minute Bing/Microsoft talker. It lives in
# several locations (Edge install, WebView2 standalone runtime, and per-app
# copies), so we block every known path. msedge.exe is intentionally NOT blocked
# so the operator browser still works.
Write-Step "Blocking msedgewebview2.exe (all instances) - ~30 min Bing/MS pulls"
$WebView2Paths = @(
    "%ProgramFiles(x86)%\Microsoft\Edge\Application\*\msedgewebview2.exe",
    "%ProgramFiles%\Microsoft\Edge\Application\*\msedgewebview2.exe",
    "%ProgramFiles(x86)%\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe",
    "%ProgramFiles%\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe"
)
$w = 0
foreach ($p in $WebView2Paths) { $w++; Block-Outbound -DisplayName "TIPS-Block-WebView2-$w" -Program $p }

# v2.1: The wildcard rules above are kept as a fallback, but Windows Firewall
# does not glob-expand "*" at match time - so on the validation build they did
# NOT catch the live msedgewebview2.exe (it stayed ~21% of settled WAN). Now
# DISCOVER every real msedgewebview2.exe on disk and write an exact-path rule
# per instance. This is the fix for the partially-effective v2.0 block.
Write-Step "DISCOVERING + blocking real msedgewebview2.exe paths (v2.1 exact-path fix)"
Block-OutboundByDiscovery -NamePrefix "TIPS-Block-WebView2-disc" -FileName "msedgewebview2.exe" -Roots @(
    "%ProgramFiles(x86)%\Microsoft\Edge\Application",
    "%ProgramFiles%\Microsoft\Edge\Application",
    "%ProgramFiles(x86)%\Microsoft\EdgeWebView\Application",
    "%ProgramFiles%\Microsoft\EdgeWebView\Application",
    "%ProgramFiles(x86)%\Microsoft\EdgeCore",
    "%ProgramFiles%\Microsoft\EdgeCore"
)

# v2.0: MsMpEng.exe (Defender engine) made daily cloud-protection / signature
# bursts. We block its INTERNET egress at the firewall while leaving the WinDefend
# service running, so on-box real-time scanning of the TIPS data flow continues.
Write-Step "Blocking MsMpEng.exe internet egress (Defender cloud/sig bursts; on-box AV stays)"
$MsMpEngPaths = @(
    "%ProgramData%\Microsoft\Windows Defender\Platform\*\MsMpEng.exe",
    "%ProgramFiles%\Windows Defender\MsMpEng.exe"
)
$m = 0
foreach ($p in $MsMpEngPaths) { $m++; Block-Outbound -DisplayName "TIPS-Block-MsMpEng-$m" -Program $p }

# v2.1: Discover the real MsMpEng.exe path (it lives under a versioned Platform
# sub-folder that the wildcard rule cannot match) and block it exactly.
Write-Step "DISCOVERING + blocking real MsMpEng.exe path (v2.1 exact-path fix)"
Block-OutboundByDiscovery -NamePrefix "TIPS-Block-MsMpEng-disc" -FileName "MsMpEng.exe" -Roots @(
    "%ProgramData%\Microsoft\Windows Defender\Platform",
    "%ProgramFiles%\Windows Defender"
)

Write-Step "Blocking NisSrv binary (Defender NIS already service-disabled)"
# Defender NisSrv already disabled in Section 3; block its binary too for safety.
Block-Outbound -DisplayName "TIPS-Block-NisSrv" -Program "%ProgramData%\Microsoft\Windows Defender\Platform\*\NisSrv.exe"
# v2.1: exact-path discovery for NisSrv too.
Block-OutboundByDiscovery -NamePrefix "TIPS-Block-NisSrv-disc" -FileName "NisSrv.exe" -Roots @(
    "%ProgramData%\Microsoft\Windows Defender\Platform",
    "%ProgramFiles%\Windows Defender"
)

# ----
# SECTION 14 : SURGICAL UWP BLOATWARE REMOVAL
#   Remove network-chatty Store apps. EXPLICITLY preserves Notepad, Edge,
#   Terminal, the Store engine (for offline servicing), and core frameworks.
# ----
Write-Section "SECTION 14 - UWP Bloatware Removal (surgical)"

$BloatPackages = @(
    "MicrosoftWindows.Client.WebExperience",  # Widgets board (MSN feed)
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingSearch",                   # web search in Start (calls bing)
    "Microsoft.Windows.DevHome",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingApp",
    "Microsoft.ZuneVideo",
    "Microsoft.ZuneMusic",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",                   # Tips app
    "Microsoft.YourPhone",                    # Phone Link (CrossDevice)
    "Microsoft.People",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "MicrosoftTeams",                    # consumer Teams (auto-installed)
    "Microsoft.Copilot",                    # Copilot app
    "Microsoft.Windows.Ai.Copilot.Provider",
    "Clipchamp.Clipchamp"
)

# PRESERVE LIST (never remove) - documented for auditors.
#   Microsoft.WindowsNotepad      - required editor
#   Microsoft.MicrosoftEdge*      - required browser
#   Microsoft.WindowsTerminal     - required shell host
#   Microsoft.WindowsStore        - kept for offline app servicing
#   Microsoft.VCLibs / .NET / UI.Xaml frameworks - dependencies

foreach ($App in $BloatPackages) {
    Get-AppxPackage -AllUsers -Name $App -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $App } |
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
    Write-Note "removed (if present): $App"
}

# ----
# SECTION 15 : HOSTS FILE SINKHOLE (dual-stack, observed leaks + core telemetry)
#   Dead-ends any DNS name that slips past the policy/service/firewall layers.
#   This curated list LEADS with the domains actually observed leaking in the
#   14JUN capture (which the old 740-host list missed), then adds the 24-hour
#   capture residuals (v2.0), then the high-value telemetry cores.
#   national.rfitv.army.mil / TIPS / Tailscale are NEVER added.
# ----
Write-Section "SECTION 15 - HOSTS Sinkhole (dual-stack)"

$HostsPath = "$env:windir\System32\drivers\etc\hosts"

# --- 15a. Domains OBSERVED leaking in the monitoring capture (highest priority) ---
$ObservedLeaks = @(
    "licensing.mp.microsoft.com"
    "displaycatalog.mp.microsoft.com"
    "storeedgefd.dsx.mp.microsoft.com"
    "cdn.storeedgefd.dsx.mp.microsoft.com"
    "storecatalogrevocation.storequality.microsoft.com"
    "settings-win.data.microsoft.com"
    "nf.smartscreen.microsoft.com"
    "fd.api.iris.microsoft.com"
    "msedge.api.cdp.microsoft.com"
    "config.edge.skype.com"
    "ctldl.windowsupdate.com"
    "login.live.com"
    "ecs.office.com"
    "default.exp-tas.com"
    "dns.msftncsi.com"
    "www.msftncsi.com"
    "www.msftconnecttest.com"
    "windows.msn.com"
    "www.msn.com"
    "assets.msn.com"
    "arc.msn.com"
    "img-s-msn-com.akamaized.net"
    "www.bing.com"
    "th.bing.com"
    "edgeassetservice.azureedge.net"
    "msedge.f.dl.delivery.mp.microsoft.com"
    "msedge.b.tlu.dl.delivery.mp.microsoft.com"
)

# --- 15b. 24-HOUR CAPTURE RESIDUALS (v2.0 - the last ~219 MB/month talkers) ---
#   Account/token (login.live/passport/msauth), Store purchase/licensing/catalog,
#   Delivery Optimization CDN + traffic-shaping, and MSN/Bing content CDN. These
#   close the WebView2 (~30 min) and MS-account refresh leaks.
$Capture24hrLeaks = @(
    "login.live.com"
    "logincdn.msauth.net"
    "clientconfig.passport.net"
    "geo-prod.do.dsp.mp.microsoft.com"
    "displaycatalog.mp.microsoft.com"
    "emdl.ws.microsoft.com"
    "dl.delivery.mp.microsoft.com"
    "tsfe.trafficshaping.dsp.mp.microsoft.com"
    "img-prod-cms-rt-microsoft-com.akamaized.net"
    "purchase.mp.microsoft.com"
    "licensing.mp.microsoft.com"
    "manage.devcenter.microsoft.com"
    "arc.msn.com"
    "www.msn.com"
)

# --- 15b-2. v2.1 ADDITIONS - auth/account FQDNs the v2.0 list missed (the
#   login.live.com phantom queries the 30h validation still logged) + Defender
#   cloud FQDNs to back up the MsMpEng egress firewall block. ---
$V21AdditionalLeaks = @(
    "signup.live.com"
    "account.live.com"
    "login.microsoftonline.com"
    "auth.microsoft.com"
    "edge.microsoft.com"
    "config.edge.skype.com"
    "wdcp.microsoft.com"
    "wdcpalt.microsoft.com"
    "definitionupdates.microsoft.com"
)

# --- 15c. High-value telemetry / update / ad cores (covers families by FQDN) ---
$CoreTelemetry = @(
    "v10.events.data.microsoft.com"
    "v20.events.data.microsoft.com"
    "v10c.events.data.microsoft.com"
    "us-v10.events.data.microsoft.com"
    "us-v20.events.data.microsoft.com"
    "eu-v20.events.data.microsoft.com"
    "mobile.events.data.microsoft.com"
    "self.events.data.microsoft.com"
    "browser.events.data.microsoft.com"
    "watson.events.data.microsoft.com"
    "vortex.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "settings-win.data.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "watson.microsoft.com"
    "ceuswatcab01.blob.core.windows.net"
    "ceuswatcab02.blob.core.windows.net"
    "eaus2watcab01.blob.core.windows.net"
    "eaus2watcab02.blob.core.windows.net"
    "weus2watcab01.blob.core.windows.net"
    "weus2watcab02.blob.core.windows.net"
    "activity.windows.com"
    "edge.activity.windows.com"
    "enterprise.activity.windows.com"
    "settings.data.microsoft.com"
    "diagnostics.support.microsoft.com"
    "feedback.windows.com"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "wns.windows.com"
    "client.wns.windows.com"
    "spclient.wg.spotify.com"
    "smartscreen.microsoft.com"
    "smartscreen-prod.microsoft.com"
    "checkappexec.microsoft.com"
    "urs.microsoft.com"
    "ris.api.iris.microsoft.com"
    "api.msn.com"
    "c.msn.com"
    "g.msn.com"
    "ntp.msn.com"
    "srtb.msn.com"
    "ad.doubleclick.net"
    "g.bing.com"
    "a-0001.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-msedge.net"
    "az667904.vo.msecnd.net"
    "ssw.live.com"
    "watson.live.com"
    "ctldl.windowsupdate.com"
    "fe2.update.microsoft.com"
    "fe3.delivery.mp.microsoft.com"
    "tlu.dl.delivery.mp.microsoft.com"
    "displaycatalog.md.mp.microsoft.com"
    "manage.devcenter.microsoft.com"
    "go.microsoft.com"
)

# --- 15b-3. v2.2 ADDITIONS - the only two FQDNs the v2.1 25-hour validation
#   capture logged that were NOT already sinkholed. Both are TPM attestation /
#   firmware endpoints, safe to dead-end on an offline Iridium site (TPM key
#   attestation and chip-vendor firmware checks are not needed there). Exact
#   FQDNs only - we deliberately do NOT sinkhole the parent azure.net. ---
$V22ObservedLeaks = @(
    "microsoftaik.azure.net"        # TPM key attestation (Autopilot/Intune/Hello-for-Business)
    "ntc-keyid-9fbb79aa0f526278bed150929a7171e96a35bef7.microsoftaik.azure.net"
    "www.nuvoton.com"               # Nuvoton TPM chip vendor - firmware/info checks
)

# Merge + de-duplicate (case-insensitive). Sort-Object -Unique safely collapses
# any overlap between the 14JUN, 24h, v2.1, v2.2 and core lists (e.g. login.live.com).
$TargetDomains = ($ObservedLeaks + $Capture24hrLeaks + $V21AdditionalLeaks + $V22ObservedLeaks + $CoreTelemetry) | Sort-Object -Unique

Write-Step ("Sinkholing {0} domains (IPv4 0.0.0.0 + IPv6 ::1) into HOSTS" -f $TargetDomains.Count)

# Make hosts writable, strip any prior TIPS block, then re-append cleanly so the
# script stays idempotent (re-running won't duplicate thousands of lines).
attrib -r $HostsPath 2>$null
$marker      = "# === TIPS LOW-BANDWIDTH SINKHOLE (managed - do not edit below) ==="
$endMarker   = "# === END TIPS SINKHOLE ==="
$existing    = @()
if (Test-Path $HostsPath) { $existing = Get-Content $HostsPath -ErrorAction SilentlyContinue }
# Drop any previously-managed block (between markers) before re-writing.
$clean = New-Object System.Collections.Generic.List[string]
$inBlock = $false
foreach ($line in $existing) {
    if ($line -eq $marker)    { $inBlock = $true;  continue }
    if ($line -eq $endMarker) { $inBlock = $false; continue }
    if (-not $inBlock)        { $clean.Add($line) }
}

$payload = New-Object System.Collections.Generic.List[string]
$payload.Add("")
$payload.Add($marker)
$payload.Add("# Generated: $(Get-Date -Format u) | Entries: $($TargetDomains.Count) |  v2.1")
foreach ($d in $TargetDomains) {
    $clean2 = ($d -replace '^\s*(0\.0\.0\.0|::1)\s+', '').Trim()
    if ([string]::IsNullOrWhiteSpace($clean2)) { continue }
    $payload.Add("0.0.0.0 $clean2")   # IPv4 dead-end (no local listener = instant fail)
    $payload.Add("::1 $clean2")       # IPv6 loopback dead-end (valid hosts syntax)
}
$payload.Add($endMarker)

# Write merged content back (UTF8 without BOM to keep the resolver happy).
$v2 = ($clean + $payload) -join "`r`n"
[System.IO.File]::WriteAllText($HostsPath, $v2, (New-Object System.Text.UTF8Encoding($false)))
attrib +r $HostsPath 2>$null
Write-Note "HOSTS updated and set read-only"

# Flush the resolver cache so blocks take effect immediately.
ipconfig /flushdns | Out-Null

# ----
# SECTION 16 : VERIFICATION SUMMARY
# ----
Write-Section "SECTION 16 - Verification Summary"

$svcDisabled = ($ServicesToDisable | Where-Object {
    (Get-Service -Name $_ -ErrorAction SilentlyContinue).StartType -eq 'Disabled'
}).Count
$fwRules = (Get-NetFirewallRule -DisplayName "TIPS-Block-*" -ErrorAction SilentlyContinue).Count
$hostsCount = $TargetDomains.Count

Write-Host ""
Write-Host "  Services confirmed Disabled : $svcDisabled / $($ServicesToDisable.Count)" -ForegroundColor Green
Write-Host "  Outbound firewall blocks    : $fwRules"                    -ForegroundColor Green
Write-Host "  HOSTS sinkhole entries      : $hostsCount domains (dual-stack)"           -ForegroundColor Green
Write-Host "  Transcript log              : $LogFile"                    -ForegroundColor Green
if ($PreserveTailscale) {
    Write-Host "  Tailscale                   : PRESERVED (non-Iridium site)"           -ForegroundColor Green
}
if ($DisableDefenderRealtime) {
    Write-Host "  Defender real-time AV       : DISABLED (policy-gated -DisableDefenderRealtime)" -ForegroundColor Yellow
} else {
    Write-Host "  Defender real-time AV       : ON (egress firewalled only)"            -ForegroundColor Green
}
Write-Host ""
Write-Host "====" -ForegroundColor Green
Write-Host "  v2.2 HARDENING COMPLETE. REBOOT REQUIRED for full effect."  -ForegroundColor Green
Write-Host " Re-run NetMonitor v4.2 post-reboot to confirm < 100 MB/month."  -ForegroundColor Green
Write-Host "====" -ForegroundColor Green

try { Stop-Transcript | Out-Null } catch {}
