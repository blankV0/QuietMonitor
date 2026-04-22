<#
.SYNOPSIS
    QuietMonitor – Zero Trust endpoint compliance agent for Windows.

.DESCRIPTION
    Collects system performance metrics and seven security control checks,
    then POSTs a JSON payload to the QuietMonitor FastAPI backend.

    Performance metrics collected
    ─────────────────────────────
      • CPU usage          (Win32_Processor / LoadPercentage)
      • RAM usage          (Win32_OperatingSystem free vs. total memory)
      • Disk usage         (Win32_LogicalDisk on C:)
      • Antivirus status   (SecurityCenter2 WMI productState bitmask)
      • Last reboot time   (Win32_OperatingSystem.LastBootUpTime → ISO-8601)

    Zero Trust security controls checked
    ──────────────────────────────────────
      1. Windows Firewall     All three profiles (Domain / Private / Public)
                              must be enabled for the check to pass.
      2. Microsoft Defender   Real-time protection state + signature age.
      3. BitLocker            C: drive ProtectionStatus via PowerShell
                              module, with manage-bde fallback.
      4. Local administrators Members of the built-in Administrators group
                              enumerated via ADSI (no net.exe dependency).
      5. RDP                  fDenyTSConnections registry value; also checks
                              Network Level Authentication (NLA) requirement.
      6. USB mass storage     USBSTOR service Start value + optional Group
                              Policy override key.
      7. Installed software   Display names from all three Uninstall registry
                              hives, deduplicated and version-tagged.

    Transport security
    ──────────────────
      • TLS 1.2 is enforced at .NET ServicePointManager level so HTTPS
        endpoints work correctly even on Windows Server 2016.
      • Invoke-RestMethod is wrapped with retry + exponential back-off so
        transient network errors do not drop an entire check-in cycle.

.PARAMETER ApiUrl
    Full URL of the /agent/update endpoint.
    Default: http://localhost:8000/agent/update
    Override for HTTPS: https://monitor.corp.example.com/agent/update

.PARAMETER IntervalSeconds
    Seconds to wait between check-ins.  Default: 300 (5 minutes).

.PARAMETER MaxApps
    Maximum number of installed-app entries sent per payload.
    Keeps payloads from growing unbounded on heavily-loaded machines.
    Default: 150.

.PARAMETER MaxRetries
    How many times to retry a failed HTTP POST before giving up.
    Default: 3.

.NOTES
    Requirements : PowerShell 5.1 or later, Windows 10 / Server 2016+.
    Elevation    : A standard user account works for most checks.
                   BitLocker volume status and Defender details may return
                   $null without elevation on some OS configurations.
    Scheduling   : Create a Task Scheduler task that runs this script every
                   5 minutes under SYSTEM or a dedicated service account.

    Manual one-shot run:
        powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1

    Run against a remote / HTTPS server:
        powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 `
            -ApiUrl "https://monitor.corp.example.com/agent/update"
#>

[CmdletBinding()]
param(
    [string] $ApiUrl         = "http://localhost:8000/agent/update",
    [int]    $IntervalSeconds = 300,
    [int]    $MaxApps        = 150,
    [int]    $MaxRetries     = 3
)

# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 0 – Transport security
#  Force TLS 1.2 for all .NET HttpWebRequest calls made by Invoke-RestMethod.
#  Without this, Windows Server 2016 / PowerShell 5 may default to TLS 1.0,
#  which many modern servers reject.
# ═══════════════════════════════════════════════════════════════════════════════
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 – Shared utilities
# ═══════════════════════════════════════════════════════════════════════════════

#  Safe-Run
#  ────────
#  Executes a script block and returns its output.
#  If the block throws for any reason (missing cmdlet, access denied,
#  WMI timeout, etc.) the $Default value is returned instead of crashing
#  the entire agent.  This makes every individual check independently
#  fault-tolerant.
function Safe-Run {
    param(
        [scriptblock] $Block,          # The code to execute
        $Default      = $null          # Fallback value on error
    )
    try   { & $Block }
    catch { $Default }
}

#  Write-CheckResult
#  ─────────────────
#  Prints a colour-coded one-liner per check to the console so an operator
#  watching the agent can immediately see which controls passed or failed
#  without trawling through verbose output.
function Write-CheckResult {
    param(
        [string] $Label,               # Short display name for the check
        $Value,                        # Raw value collected
        [string] $PassText  = "PASS",  # Text shown when the check is healthy
        [string] $FailText  = "FAIL",  # Text shown when the check indicates a risk
        [scriptblock] $PassWhen = { $args[0] -eq $true }  # Predicate: value → bool
    )
    $ok    = & $PassWhen $Value
    $color = if ($ok) { "Green" } elseif ($null -eq $Value) { "DarkYellow" } else { "Red" }
    $state = if ($null -eq $Value) { "N/A" } elseif ($ok) { $PassText } else { $FailText }
    Write-Host ("    {0,-28} [{1}]" -f $Label, $state) -ForegroundColor $color
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 – Performance metrics
#  These are the original QuietMonitor health indicators (CPU / RAM / Disk /
#  Antivirus / last reboot).  They are kept alongside the security controls
#  so the backend stores a unified snapshot per check-in.
# ═══════════════════════════════════════════════════════════════════════════════

function Get-CpuUsage {
    <#
    .SYNOPSIS Returns current CPU usage as a percentage (0–100).
    .NOTES
        Win32_Processor.LoadPercentage is sampled by the WMI provider at a
        ~1-second interval and represents the average utilisation across
        all logical processors.  We average across sockets (multi-CPU).
    #>
    Safe-Run {
        $pct = (Get-WmiObject Win32_Processor |
                Measure-Object -Property LoadPercentage -Average).Average
        [double]$pct
    }
}

function Get-RamUsage {
    <#
    .SYNOPSIS Returns RAM consumption as a percentage (0–100).
    .NOTES
        Win32_OperatingSystem reports sizes in KB.
        FreePhysicalMemory is subtracted from TotalVisibleMemorySize to
        derive the used amount.  Hardware-reserved memory is excluded from
        TotalVisibleMemorySize, so the percentage aligns with Task Manager.
    #>
    Safe-Run {
        $os   = Get-WmiObject Win32_OperatingSystem
        $used = $os.TotalVisibleMemorySize - $os.FreePhysicalMemory
        [Math]::Round(($used / $os.TotalVisibleMemorySize) * 100, 1)
    }
}

function Get-DiskUsage {
    <#
    .SYNOPSIS Returns C: drive utilisation as a percentage (0–100).
    .NOTES
        Uses Win32_LogicalDisk filtered to the system drive.
        Size and FreeSpace are both in bytes.
    #>
    Safe-Run {
        $d = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
        [Math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 1)
    }
}

function Get-AntivirusStatus {
    <#
    .SYNOPSIS Returns the registration / health state of the first AV product
               known to Windows Security Center.
    .NOTES
        The productState integer encodes three fields in hex:
          Bits 19-12  product type (antivirus, firewall, …)
          Bits 11- 8  real-time protection state  (10 = on, 00 = off)
          Bits  7- 0  definition update state      (10 = up-to-date)
        We extract the RTP byte (positions 2–3 in a 6-digit hex string).
        This namespace only exists on desktop Windows; on Server Core the
        function falls back to "Unknown".
    #>
    Safe-Run {
        $av = Get-WmiObject -Namespace "root\SecurityCenter2" `
                            -Class     AntiVirusProduct `
                            -ErrorAction Stop |
              Select-Object -First 1

        if ($null -eq $av) { return "Not found" }

        # Convert productState to a zero-padded 6-digit hex string, e.g. "397312"
        $hex    = [Convert]::ToString($av.productState, 16).PadLeft(6, '0')
        $rtpHex = $hex.Substring(2, 2)   # bytes 2-3 represent RTP state

        if ($rtpHex -eq "10") { "Enabled" } else { "Disabled" }
    } -Default "Unknown"
}

function Get-LastReboot {
    <#
    .SYNOPSIS Returns the last boot time as an ISO-8601 string.
    .NOTES
        Win32_OperatingSystem.LastBootUpTime is a DMTF datetime string.
        ConvertToDateTime() translates it to a .NET DateTime, which is
        then formatted as ISO-8601 so it can be round-tripped through JSON
        and parsed correctly by Python's datetime.fromisoformat().
    #>
    Safe-Run {
        $os = Get-WmiObject Win32_OperatingSystem
        $os.ConvertToDateTime($os.LastBootUpTime).ToString("o")
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 – Zero Trust security checks
#  Each function returns $true (control PASS), $false (control FAIL), or
#  $null (data unavailable – agent lacks permission or cmdlet is missing).
#  $null is intentionally distinct from $false so the risk engine can
#  differentiate "we know it's off" from "we couldn't check".
# ═══════════════════════════════════════════════════════════════════════════════

# ── 3a. Windows Firewall ────────────────────────────────────────────────────
function Get-FirewallStatus {
    <#
    .SYNOPSIS
        Returns $true only if ALL three firewall profiles are enabled.
    .DESCRIPTION
        Windows maintains three independent firewall profiles:
          • Domain   – applied when the machine is joined to a domain network
          • Private  – applied on trusted home / work networks
          • Public   – applied on untrusted networks (airports, hotels, etc.)
        Zero Trust requires all three to be active; a machine is only
        considered compliant if none of the profiles has been disabled.
        Get-NetFirewallProfile is available from Windows 8 / Server 2012 R2
        via the NetSecurity module (loaded automatically by Windows).
    .OUTPUTS [bool] or $null
    #>
    Safe-Run {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        # Log per-profile status so operators know exactly which profile failed
        foreach ($p in $profiles) {
            $state = if ($p.Enabled) { "ON " } else { "OFF" }
            Write-Verbose "  Firewall profile '$($p.Name)': $state"
        }

        # The check passes only when every profile reports Enabled = True
        $allOn = ($profiles | Where-Object { -not $_.Enabled }).Count -eq 0
        [bool]$allOn
    }
}


# ── 3b. Microsoft Defender ──────────────────────────────────────────────────
function Get-DefenderStatus {
    <#
    .SYNOPSIS
        Returns $true if Defender real-time protection is active and
        signature definitions are not critically out-of-date.
    .DESCRIPTION
        Get-MpComputerStatus (from the Defender PowerShell module, present
        on all Windows 10 / Server 2016+ systems) exposes:
          • RealTimeProtectionEnabled  – whether on-access scanning is active
          • AntivirusSignatureAge      – days since the last definition update
        A definition age > 7 days is treated as a failed control because
        outdated signatures leave the machine vulnerable to recent threats.
        Both sub-checks must pass for the overall result to be $true.
    .OUTPUTS [bool] or $null
    #>
    Safe-Run {
        $s = Get-MpComputerStatus -ErrorAction Stop

        $rtpOn     = [bool]$s.RealTimeProtectionEnabled
        # Signature age in whole days; treat null/missing as unknown (0 = current)
        $sigAgeDays = if ($s.AntivirusSignatureAge -is [int]) { $s.AntivirusSignatureAge } else { 0 }
        $sigsOk    = $sigAgeDays -le 7

        Write-Verbose "  Defender RTP: $rtpOn  |  Signature age: ${sigAgeDays}d (ok=$sigsOk)"

        # Both real-time protection AND reasonably fresh signatures required
        [bool]($rtpOn -and $sigsOk)
    }
}


# ── 3c. BitLocker ───────────────────────────────────────────────────────────
function Get-BitLockerStatus {
    <#
    .SYNOPSIS
        Returns $true if the C: system drive is BitLocker-encrypted and
        protection is currently turned on (not suspended).
    .DESCRIPTION
        Strategy 1 – Get-BitLockerVolume (requires the BitLocker feature /
        RSAT module, present on Windows 10 Pro/Enterprise and most servers):
          ProtectionStatus values: 'On' = protected, 'Off' = not encrypted
          or suspended.

        Strategy 2 – manage-bde.exe fallback used when the PowerShell module
        is absent (e.g. Windows 10 Home or stripped server images):
          manage-bde -status C: outputs a block containing the line
          "Protection Status: Protection On" when the drive is protected.

        $null is returned only when both strategies fail, which typically
        means the agent lacks elevation or neither tool is available.
    .OUTPUTS [bool] or $null
    #>

    # ── Strategy 1: native PowerShell module ──────────────────────────────
    $result = Safe-Run {
        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        Write-Verbose "  BitLocker volume status: $($vol.ProtectionStatus)  " +
                      "Encryption: $($vol.EncryptionPercentage)%"
        [bool]($vol.ProtectionStatus -eq 'On')
    }

    if ($null -ne $result) { return $result }

    # ── Strategy 2: manage-bde.exe fallback ───────────────────────────────
    Safe-Run {
        # manage-bde may not exist on Home editions; if it fails Safe-Run
        # will catch the terminating error and return $null.
        $output = & manage-bde -status C: 2>&1
        Write-Verbose "  manage-bde output (trimmed): $(($output | Select-String 'Protection') -join ' ')"
        [bool]($output -match "Protection Status:\s+Protection On")
    }
}


# ── 3d. Local administrator accounts ───────────────────────────────────────
function Get-LocalAdmins {
    <#
    .SYNOPSIS
        Returns an array of names belonging to the local Administrators group.
    .DESCRIPTION
        Uses the ADSI WinNT provider to enumerate group membership, which is
        more reliable and locale-independent than parsing the output of
        "net localgroup Administrators":
          • Works on non-English Windows (the group SID S-1-5-32-544 is
            resolved via ADSI regardless of the display name language).
          • Returns individual account names, not domain\account strings,
            for consistent matching in the risk engine.
        Falls back to net.exe parsing if ADSI throws (rare edge cases on
        workgroup machines with restricted COM policies).
    .OUTPUTS [string[]] – may be an empty array, never $null
    #>

    # ── Strategy 1: ADSI WinNT provider ───────────────────────────────────
    $members = Safe-Run {
        # Bind to the local computer's Administrators group via the well-
        # known SID alias.  WinNT:// uses the local SAM database.
        $group   = [ADSI]"WinNT://$($env:COMPUTERNAME)/Administrators,group"
        $members = @($group.Invoke("Members") | ForEach-Object {
            $adsiObj = [ADSI]$_
            # Extract just the account name (not the full path)
            $adsiObj.Name
        } | Where-Object { $_ })

        Write-Verbose "  ADSI local admins: $($members -join ', ')"
        $members
    }

    if ($null -ne $members) { return $members }

    # ── Strategy 2: net.exe parsing fallback ──────────────────────────────
    Safe-Run {
        # Filter out the header/footer lines that net.exe emits:
        #   "Alias name   Administrators"
        #   "Comment      ..."
        #   "Members"
        #   "------------------"
        #   "The command completed successfully."
        $lines = net localgroup Administrators 2>$null |
                 Where-Object {
                     $_ -notmatch "^(Alias name|Comment|Members|---|\s*$|The command)"
                 }
        @($lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    } -Default @()
}


# ── 3e. Remote Desktop Protocol ─────────────────────────────────────────────
function Get-RdpStatus {
    <#
    .SYNOPSIS
        Returns $true if RDP is currently enabled on this machine.
    .DESCRIPTION
        Two registry values govern RDP access:

        HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server
            fDenyTSConnections   0 = RDP enabled  (deny = false)
                                 1 = RDP disabled (deny = true)

        HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
            UserAuthentication   1 = NLA required (more secure)
                                 0 = NLA not required (legacy/less secure)

        The function returns $true (RDP is on) whenever fDenyTSConnections
        equals 0, regardless of NLA state.  NLA enforcement is reported
        separately via Write-Verbose so operators can see whether RDP-enabled
        machines at least require Network Level Authentication.
    .OUTPUTS [bool] or $null
    #>
    Safe-Run {
        $tsPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $deny    = (Get-ItemProperty -Path $tsPath -Name "fDenyTSConnections" `
                                     -ErrorAction Stop).fDenyTSConnections

        # Also read NLA setting for informational verbose output
        $nlaPath = "$tsPath\WinStations\RDP-Tcp"
        $nla     = Safe-Run {
            (Get-ItemProperty -Path $nlaPath -Name "UserAuthentication" `
                              -ErrorAction Stop).UserAuthentication
        }
        $nlaText = switch ($nla) { 1 { "NLA required" } 0 { "NLA NOT required" } default { "NLA unknown" } }
        Write-Verbose "  RDP fDenyTSConnections=$deny  |  $nlaText"

        # RDP is enabled when fDenyTSConnections is 0 (zero means "do NOT deny")
        [bool]($deny -eq 0)
    }
}


# ── 3f. USB mass storage ─────────────────────────────────────────────────────
function Get-UsbStorageStatus {
    <#
    .SYNOPSIS
        Returns $true if the USB mass-storage class driver is enabled
        (i.e. USB drives can be connected and used).
    .DESCRIPTION
        Windows controls USB storage access through two mechanisms:

        1. USBSTOR service start type
           HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR  Start
             3 = SERVICE_DEMAND_START  → driver loads on demand (USB enabled)
             4 = SERVICE_DISABLED       → driver will not load (USB blocked)

        2. Group Policy registry override (takes precedence over service)
           HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices
           \{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
             Deny_Write  1 = write blocked   (partial restriction)
             Deny_Read   1 = read  blocked   (full restriction)

        This function checks both paths.  If the service is disabled OR
        if Group Policy has blocked read access, the control is considered
        disabled (returns $false).  Write-only blocks are noted in verbose
        output but do not flip the result to $false because read-only access
        is a partial control rather than a full block.
    .OUTPUTS [bool] or $null
    #>
    Safe-Run {
        # ── Check 1: USBSTOR service start type ───────────────────────────
        $svcPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
        $startVal = (Get-ItemProperty -Path $svcPath -Name "Start" `
                                       -ErrorAction Stop).Start
        # 4 = SERVICE_DISABLED, anything else means the driver can load
        $svcEnabled = ($startVal -ne 4)
        Write-Verbose "  USBSTOR service Start=$startVal  (enabled=$svcEnabled)"

        # ── Check 2: Group Policy removable storage restrictions ──────────
        $gpGuid   = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"   # USB disk class GUID
        $gpPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\$gpGuid"
        $denyRead = Safe-Run {
            (Get-ItemProperty -Path $gpPath -Name "Deny_Read" -ErrorAction Stop).Deny_Read
        } -Default 0
        $denyWrite = Safe-Run {
            (Get-ItemProperty -Path $gpPath -Name "Deny_Write" -ErrorAction Stop).Deny_Write
        } -Default 0
        Write-Verbose "  GP removable storage: Deny_Read=$denyRead  Deny_Write=$denyWrite"

        # USB storage is effectively enabled unless:
        #   a) the USBSTOR driver is set to Disabled, OR
        #   b) Group Policy has blocked read access (full block)
        $gpBlocked = ($denyRead -eq 1)
        [bool]($svcEnabled -and -not $gpBlocked)
    }
}


# ── 3g. Installed software ───────────────────────────────────────────────────
function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Returns a deduplicated, sorted array of installed application names
        (with versions where available).
    .DESCRIPTION
        Reads from three registry hive locations:
          1. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
             Native 64-bit installers on 64-bit Windows.
          2. HKLM\SOFTWARE\WOW6432Node\...\Uninstall
             32-bit installers running under WOW64 on 64-bit Windows.
          3. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
             Per-user installations (ClickOnce, user-scoped installers, etc.)

        Entries are filtered to those with a non-blank DisplayName.
        Duplicates (same name across hives) are removed.
        The list is capped at $MaxApps entries to prevent excessively large
        payloads when a machine has hundreds of installed packages.

        Each entry is formatted as "Name (vX.Y.Z)" when a DisplayVersion is
        available, otherwise just the DisplayName.  This lets the risk engine
        and compliance UI show version information without needing a separate
        field.
    .OUTPUTS [string[]] – may be empty, never $null
    #>
    Safe-Run {
        $hives = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $apps = Get-ItemProperty $hives -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
                Select-Object DisplayName, DisplayVersion |
                # Deduplicate by display name (case-insensitive)
                Group-Object -Property { $_.DisplayName.Trim().ToLower() } |
                ForEach-Object { $_.Group | Select-Object -First 1 } |
                Sort-Object DisplayName |
                Select-Object -First $MaxApps

        # Format each entry as "AppName" or "AppName (v1.2.3)".
        # Strip null characters (U+0000) from registry strings – some
        # installers leave padding null bytes in DisplayName/DisplayVersion
        # which produce invalid JSON control characters and cause the backend
        # to reject the payload with a 400 error.
        @($apps | ForEach-Object {
            $name = $_.DisplayName.Trim() -replace '\x00', ''
            if ($_.DisplayVersion -and $_.DisplayVersion.Trim() -ne "") {
                $ver = $_.DisplayVersion.Trim() -replace '\x00', ''
                "$name (v$ver)"
            } else {
                $name
            }
        } | Where-Object { $_ -ne "" })
    } -Default @()
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 – HTTP transport with retry / back-off
#  Invoke-RestMethod can fail due to transient network issues (DNS hiccup,
#  server restart, brief firewall rule change, etc.).  Rather than silently
#  dropping the check-in, we retry up to $MaxRetries times with exponential
#  back-off (2s → 4s → 8s …).  If all retries are exhausted the failure
#  is logged but the agent continues running and will try again next cycle.
# ═══════════════════════════════════════════════════════════════════════════════

function Send-Payload {
    <#
    .SYNOPSIS  POST $JsonBody to $Uri with retry logic.
    .OUTPUTS   The deserialized response object, or $null on permanent failure.
    #>
    param(
        [string] $Uri,
        [string] $JsonBody
    )

    $attempt    = 0
    $waitSec    = 2    # Initial back-off delay in seconds (doubles each retry)

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            # Encode the JSON body as UTF-8 bytes explicitly.  In PS 5.1,
            # Invoke-RestMethod encodes string bodies using the system ANSI
            # code page by default, which corrupts non-ASCII characters.
            # Sending a [byte[]] body bypasses that and guarantees UTF-8
            # on the wire, matching what FastAPI/Starlette expects.
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
            $response = Invoke-RestMethod `
                -Uri         $Uri `
                -Method      POST `
                -Body        $bodyBytes `
                -ContentType "application/json; charset=utf-8" `
                -ErrorAction Stop

            return $response   # Success – exit the retry loop immediately
        }
        catch {
            $errMsg = $_.Exception.Message
            if ($attempt -lt $MaxRetries) {
                Write-Warning "  POST attempt $attempt/$MaxRetries failed: $errMsg"
                Write-Warning "  Retrying in ${waitSec}s …"
                Start-Sleep -Seconds $waitSec
                $waitSec *= 2   # Exponential back-off: 2s, 4s, 8s, …
            } else {
                Write-Warning "  All $MaxRetries POST attempts failed.  Last error: $errMsg"
            }
        }
    }
    return $null
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 – Main collection + send function
#  Send-Metrics is called once per interval.  It orchestrates all collectors,
#  assembles the payload hashtable, serializes to JSON, sends via Send-Payload,
#  and prints a structured summary to the console.
# ═══════════════════════════════════════════════════════════════════════════════

function Send-Metrics {

    $hostname  = [System.Net.Dns]::GetHostName()

    # Resolve the first IPv4 address on a physical or wireless adapter.
    # Wildcard matching handles common adapter name patterns across vendors.
    $ipAddress = (
        Get-NetIPAddress -AddressFamily IPv4 `
                         -InterfaceAlias "*Ethernet*","*Wi-Fi*","*Local*","*LAN*" `
                         -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.*" } |   # exclude APIPA
        Select-Object -First 1
    ).IPAddress

    Write-Host ""
    Write-Host ("═" * 60) -ForegroundColor DarkGray
    Write-Host "  QuietMonitor check-in  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    $ipDisplay = if ($ipAddress) { $ipAddress } else { 'n/a' }
    Write-Host "  Host: $hostname   IP: $ipDisplay" -ForegroundColor Gray
    Write-Host ("═" * 60) -ForegroundColor DarkGray

    # ── Collect performance metrics ──────────────────────────────────────
    Write-Host "  [Performance]" -ForegroundColor Cyan
    $cpu     = Get-CpuUsage
    $ram     = Get-RamUsage
    $disk    = Get-DiskUsage
    $av      = Get-AntivirusStatus
    $reboot  = Get-LastReboot

    Write-Host ("    CPU: {0}%  RAM: {1}%  Disk: {2}%  AV: {3}" -f $cpu, $ram, $disk, $av) -ForegroundColor Gray

    # ── Collect Zero Trust security controls ─────────────────────────────
    Write-Host "  [Security Controls]" -ForegroundColor Cyan

    $firewall = Get-FirewallStatus
    Write-CheckResult "Windows Firewall (all profiles)" $firewall `
        -PassWhen { $args[0] -eq $true }

    $defender = Get-DefenderStatus
    Write-CheckResult "Defender RTP + signatures ≤7d"  $defender `
        -PassWhen { $args[0] -eq $true }

    $bitlocker = Get-BitLockerStatus
    Write-CheckResult "BitLocker (C: drive)"           $bitlocker `
        -PassWhen { $args[0] -eq $true }

    $localAdmins = Get-LocalAdmins
    # For display: flag if non-default accounts exist in the admin group
    $noise       = @("administrator","domain admins","domain admins (group)")
    $extraAdmins = @($localAdmins | Where-Object { $noise -notcontains $_.ToLower() })
    Write-CheckResult "No extra local admins"          ($extraAdmins.Count -eq 0) `
        -PassText "PASS ($($localAdmins.Count) member(s))" `
        -FailText "FAIL ($($extraAdmins.Count) extra: $($extraAdmins -join ', '))" `
        -PassWhen { $args[0] -eq $true }

    $rdp = Get-RdpStatus
    Write-CheckResult "RDP disabled"                   $rdp `
        -PassText "PASS (RDP off)" -FailText "FAIL (RDP on)" `
        -PassWhen { $args[0] -eq $false }

    $usb = Get-UsbStorageStatus
    Write-CheckResult "USB storage blocked"            $usb `
        -PassText "PASS (blocked)" -FailText "FAIL (allowed)" `
        -PassWhen { $args[0] -eq $false }

    $apps = Get-InstalledSoftware
    Write-Host ("    Installed apps: {0} entries collected" -f $apps.Count) -ForegroundColor Gray

    # ── Assemble JSON payload ─────────────────────────────────────────────
    # The payload schema matches AgentUpdate in backend/app/schemas.py.
    # All fields are Optional on the backend so an older agent that omits
    # security fields will still be accepted without error.
    #
    # Wrap list fields in @() to guarantee they serialize as JSON arrays
    # (not objects) even when empty – ConvertTo-Json can produce {} for
    # an empty/null collection unless it is explicitly typed as an array.
    # Filter out $null entries in case a collector returned nothing via the
    # pipeline (PS pipeline drops empty arrays, leaving $null which would
    # produce [null] in JSON rather than []).
    $localAdmins = @($localAdmins | Where-Object { $null -ne $_ })
    $apps        = @($apps        | Where-Object { $null -ne $_ })

    $payload = [ordered]@{
        # ── Identity ──────────────────────────────────────────────────────
        hostname         = $hostname
        ip_address       = $ipAddress
        current_user     = $env:USERNAME

        # ── Performance ───────────────────────────────────────────────────
        cpu_usage        = $cpu
        ram_usage        = $ram
        disk_usage       = $disk
        antivirus_status = $av
        last_reboot      = $reboot

        # ── Security controls ─────────────────────────────────────────────
        # Each field maps directly to a column in the Machine ORM model.
        # The risk engine on the server recalculates risk_score, trust_level,
        # and failed_checks from these values after every check-in.
        firewall_enabled    = $firewall
        defender_enabled    = $defender
        bitlocker_enabled   = $bitlocker
        local_admins        = $localAdmins      # array of account name strings
        rdp_enabled         = $rdp
        usb_storage_enabled = $usb
        installed_apps      = $apps             # array of "Name (vX.Y)" strings
    }

    # ConvertTo-Json -Depth 3 handles the nested arrays (local_admins,
    # installed_apps) correctly.  -Compress removes whitespace to keep the
    # payload compact on the wire.
    $json = $payload | ConvertTo-Json -Depth 3 -Compress

    # ── Send and display result ───────────────────────────────────────────
    Write-Host "  [Sending to $ApiUrl]" -ForegroundColor Cyan
    $response = Send-Payload -Uri $ApiUrl -JsonBody $json

    if ($null -ne $response) {
        $trustColor = switch ($response.trust_level) {
            "trusted"  { "Green"  }
            "warning"  { "Yellow" }
            "critical" { "Red"    }
            default    { "Gray"   }
        }
        Write-Host ("  [OK] Accepted  |  Trust: {0}  |  Risk: {1}/100  |  Failed checks: {2}" -f
            $response.trust_level,
            $response.risk_score,
            (($response.failed_checks -join ", ") -replace "^$", "none")
        ) -ForegroundColor $trustColor
    } else {
        Write-Host "  ✗ Check-in failed after $MaxRetries attempts." -ForegroundColor Red
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 – Entry point / main loop
#  The agent runs indefinitely until the user presses Ctrl+C or the hosting
#  process (Task Scheduler, NSSM service wrapper, etc.) terminates it.
#  Each iteration calls Send-Metrics then sleeps for $IntervalSeconds.
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  QuietMonitor Zero Trust Agent" -ForegroundColor Cyan
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  API endpoint : $ApiUrl"            -ForegroundColor Gray
Write-Host "  Interval     : $IntervalSeconds s" -ForegroundColor Gray
Write-Host "  Max apps     : $MaxApps"           -ForegroundColor Gray
  $tlsProtocol = [Net.ServicePointManager]::SecurityProtocol
  Write-Host "  TLS protocol : $tlsProtocol" -ForegroundColor Gray
Write-Host "  Press Ctrl+C to stop."             -ForegroundColor DarkGray
Write-Host ""

# Run the first check-in immediately on startup, then enter the timed loop
while ($true) {
    Send-Metrics
    $nextTime = (Get-Date).AddSeconds($IntervalSeconds).ToString('HH:mm:ss')
    $msg = "  Next check-in in {0}s  ({1})" -f $IntervalSeconds, $nextTime
    Write-Host $msg -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds $IntervalSeconds
}
