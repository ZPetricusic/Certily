function Get-AuditingPolicy {
    <#
    .SYNOPSIS
        Checks the necessary audit policy settings to ensure that template issuing requests are logged.

    .DESCRIPTION
        Checks both the local audit policy (requires admin rights) and the CA settings to ensure the
        'Issue and manage certificate requests' audit flag is enabled.

    .PARAMETER PolicyToCheck
        Flag indicating whether the audit policy or CA settings should be checked.
        If ommited, both checks are performed.
    #>

    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PolicyCheckMode]$PolicyToCheck
    )

    if ($null -eq $PolicyToCheck -or $PolicyToCheck -eq [PolicyCheckMode]::auditingPolicy) {
        Write-Host "[*] Checking local auditing policy settings" -ForegroundColor Cyan
        $auditpolData = auditpol.exe /get /subcategory:"Certification Services" /r | ConvertFrom-Csv
        if ($($auditpolData | Select-Object -ExpandProperty "Inclusion Setting") -ieq 'Success and Failure') {
            Write-Host "[+] Auditing policy for 'Certification Services' already enabled, skipping setup"
            $Script:auditpolSetup = $true
        } else {
            Write-Host "[!] Auditing policy for 'Certification Services' not enabled, will be set up"
            $Script:auditpolSetup = $false
        }
    }

    if ($null -eq $PolicyToCheck -or $PolicyToCheck -eq [PolicyCheckMode]::caPolicy) {
        Write-Host "[*] Checking CA auditing settings" -ForegroundColor Cyan
        
        $ISSUE_AND_MANAGE_CERTS_FLAG = 0x4
        $currentCA = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active
        $auditSettingsPath = "HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$currentCA"
        $auditBitmaskValue = Get-ItemPropertyValue -Path $auditSettingsPath -Name "AuditFilter"

        if (($auditBitmaskValue -band $ISSUE_AND_MANAGE_CERTS_FLAG) -ne 0) {
            Write-Host "[+] CA auditing flag for 'Issue and Manage Certificates' already enabled, skipping setup"
            $Script:caSetup = $true
        } else {
            Write-Host "[!] CA auditing flag for 'Issue and Manage Certificates' not enabled, will be set up"
            $Script:caSetup = $false
        }
    }
}

function Set-AuditingPolicy {
    <#
    .SYNOPSIS
        Configures the audit policy to ensure that template issuing requests are logged.
    
    .DESCRIPTION
        Ensures that the correct auditing settings 
        (both in the Local Auditing Policy and in the CA configuration itself)
        are applied to enable the generation of template issuing request events,
        4886 (Certification Services).
    #>

    if (-not $Script:auditpolSetup) {
        Write-Host "[*] Enabling success and failure audit events for 'Certification Services'" -ForegroundColor Cyan
        Write-Warning "`n`nNote that this script only configures the auditing policy locally! Group policy definitions and similar mechanisms should still take precedence, potentially disabling the audit policy! Ensure that the policy is not being overwritten by an existing GPO, or configure the GPO to enforce auditing of Certification Services!`n`n"
        
        auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable
        auditpol.exe /get /subcategory:"Certification Services"
    }
    
    do {
        if (-not $Script:caSetup) {
            Write-Host "`n[*] Template issuance auditing has not been enabled, opening the Certification Authority snap-in" -ForegroundColor Cyan
            Write-Host @"
[*] To enable template issuance auditing via the Cert Authority snap-in:
`t1. Find your CA in the snap-in
`t2. Right-click -> Properties -> Auditing
`t3. Ensure that 'Issue and manage certificate requests' is checked
`t4. Apply the settings and make sure to restart the CA by running 'net stop certsvc && net start certsvc' - the settings will not be applied until the CA service is restarted.
"@

            Start-Process "$env:windir\System32\certsrv.msc"
            Read-Host "`tOnce auditing has been enabled, press [Return] to continue"
        }

        Get-AuditingPolicy -PolicyToCheck caPolicy
    } while (-not $Script:caSetup)
}

function New-CanaryScript {
    <#
    .SYNOPSIS
        Generates a Powershell script to be used with a Canary trigger.
    
    .DESCRIPTION
        Populates the template fields based on the provided template name
        and Canary Web Bug URL and returns a base64-encoded Powershell
        script which will send an HTTP request with the necessary event data
        to the provided Canary URL. Note that the Canary POST body is limited
        to 50 characters, so information has to be choosen wisely :(
    
    .PARAMETER TemplateName
        The name of the honeypot template.
    
    .PARAMETER CanaryUrl
        The URL of the Canary Web Bug token.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,

        [Parameter(Mandatory = $true)]
        [string]$CanaryUrl
    )

    $template = @'
$TemplateName     = '<TEMPLATE_NAME>'
$CanaryTokensWebBugURL = '<CANARY_URL>'

# get the latest request event
$HoneyEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = 4886 } | `
			  Where-Object { $_.Message -match "Requested Template:\s+($TemplateName)\s" } | `
              Sort-Object -Property TimeCreated -Descending | Select-Object -First 1 | `
              Select-Object -ExpandProperty Message

$HoneyEvent -match 'Request ID:\s+(\d+)'
$RequestId = $matches[1]

$HoneyEvent -match 'Requester:\s+(.+?)\s'
$Requester = $matches[1]

$HoneyEvent -match 'SAN:(.+?)\s'
if ($null -ne $matches[1]) {
    $SAN = $matches[1]
} else {
    $SAN = "n/a"
}

$PostBody = "ReqId:$RequestId|ReqUsr:$Requester|SAN:$SAN"
$PostBody = $PostBody.Substring(0, [Math]::Min($PostBody.Length, 50))

Invoke-WebRequest -UseBasicParsing -Uri $CanaryTokensWebBugURL `
				  -Method Post -Body @{
                    Message = $PostBody
				 }
'@

    $template = $template.Replace('<TEMPLATE_NAME>', $TemplateName).Replace('<CANARY_URL>', $CanaryUrl)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($template))
}

function Remove-WMISubscription {
    <#
    .SYNOPSIS
        Removes any existing WMI subscriptions related to a template.
    
    .DESCRIPTION
        Removes any existing WMI subscriptions related to a template.
    
    .PARAMETER TemplateName
        The name of the honeypot template related to the WMI subscription.

    .PARAMETER CheckOnly
        Use this parameter if WMI subscriptions should only be checked for, and not automatically deleted.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$TemplateName,

        [Parameter(Mandatory=$false)]
        [switch]$CheckOnly = $false
    )

    $EventFilterName    = "Certily - $TemplateName was requested (Event Filter)"
    $ConsumerFilterName = "Certily - $TemplateName was requested (Canary Token Alert)"

    Write-Host "[*] Cleaning up WMI artifacts..." -ForegroundColor Yellow
    $EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$ConsumerFilterName'" -ErrorAction SilentlyContinue
    $EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilterName'" -ErrorAction SilentlyContinue
    $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding" -ErrorAction SilentlyContinue
    
    if ($CheckOnly -and ($EventConsumerToCleanup -or $EventFilterToCleanup -or $FilterConsumerBindingToCleanup)) {
        do {
            $deleteWmi = Read-Host "A WMI subscription for the specified template was found - would you like to remove that as well? (y/n)"
            if ($deleteWmi -ieq 'y') {
                $FilterConsumerBindingToCleanup | Remove-WmiObject -ErrorAction Stop
                $EventConsumerToCleanup | Remove-WmiObject -ErrorAction Stop
                $EventFilterToCleanup | Remove-WmiObject -ErrorAction Stop
                Write-Host "[+] WMI cleanup complete!" -ForegroundColor Green
            } elseif ($deleteWmi -ieq 'n') {
                Write-Host "[!] Not removing WMI subscription for template $TemplateName" -ForegroundColor Yellow
            } else {
                Write-Host "[*] Please enter y or n." -ForegroundColor Yellow
            }
        } while (-not ($deleteWmi -iin 'y','n'))
    }

    if (-NOT $CheckOnly) {
        $FilterConsumerBindingToCleanup | Remove-WmiObject -ErrorAction Stop
        $EventConsumerToCleanup | Remove-WmiObject -ErrorAction Stop
        $EventFilterToCleanup | Remove-WmiObject -ErrorAction Stop
        Write-Host "[+] WMI cleanup complete!" -ForegroundColor Green
    }
}

function Set-CanaryTokenAlert {
    <#
    .SYNOPSIS
        Configures a WMI event subscription to trigger a Canary Token alert.
    
    .DESCRIPTION
        Employs a WMI event subscription script to trigger 
        a Canary Token web bug alert every time a honeypot
        template is requested.
    
    .PARAMETER TemplateName
        The name for the new certificate template for whose issuance
        monitoring should be set up.

    .PARAMETER UsageMode
        A usage mode enum indicating whether the WebBug URL is provided
        as an immediate value, or if the API key is provided and should
        be used to generate the URL.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [CanaryUsageMode]$UsageMode
    )

    $EventFilterName    = "Certily - $TemplateName was requested (Event Filter)"
    $ConsumerFilterName = "Certily - $TemplateName was requested (Canary Token Alert)"
    
    $CanaryKind         = "http"
    $CanaryMemo         = "Certily - Web Bug token for the '$TemplateName' ADCS certificate template"

    $CanaryTokensWebBugURL = ""

    if ($UsageMode -eq [CanaryUsageMode]::WebBugUrl) {
        $CanaryTokensWebBugURL = Read-Host "Enter your Canary Token Web Bug URL (https://canarytokens.org/nest/ -> create a new Web Bug token)"
        if (-NOT ([uri]::IsWellFormedUriString($CanaryTokensWebBugURL, 'Absolute') -and ([uri] $CanaryTokensWebBugURL).Scheme -in 'https','http')) {
            Write-Host -ForegroundColor Red "Provided Canary Token URL is not a valid HTTP(S) URL!"
            $script:CanarySucceeded = $false
            return
        }
    } else {
        $CanaryTokensDomainHash = Read-Host "Enter your Canary Tokens Enterprise console domain hash (first part in your console FQDN, i.e., https://<DOMAIN_HASH>.canary.tools)"
        $CanaryTokensApiKey = Read-Host "Enter your Canary Tokens Enterprise console API key with 'Canarytoken Deploy' permissions over the target flock"

        if (-not ($CanaryTokensApiKey -match '^[0-9a-f]{44,}$')) {
            Write-Host -ForegroundColor Red "Provided Canary API key does not match the expected format (44 hex characters)!"
            $script:CanarySucceeded = $false
            return
        }

        try {
            $CanaryToken = Invoke-RestMethod -Uri "https://$CanaryTokensDomainHash.canary.tools/api/v1/canarytoken/create" -Body @{
                "auth_token" = $CanaryTokensApiKey
                "memo"       = $CanaryMemo
                "kind"       = $CanaryKind
            } -Method Post -EA Stop
        } catch {
            Write-Host -ForegroundColor Red "[!] Error while calling Canary API (HTTP error $($_.Exception.Response.StatusCode.value__)): $($_.ErrorDetails.Message.Trim())"
            $script:CanarySucceeded = $false
            return
        }

        Write-Host -ForegroundColor Green "[+] Canary token created!"
        $CanaryToken.canarytoken | Format-List
        $CanaryTokensWebBugURL = $CanaryToken.canarytoken.url
    }

    $script:CanarySucceeded = $true
    
    try{
        $FilterArgs = @{
            Name            = $EventFilterName
            EventNameSpace  = "root/CimV2"
            QueryLanguage   = "WQL"
            Query           = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '4886' AND TargetInstance.LogFile = 'Security' AND TargetInstance.Message LIKE '%$TemplateName%'"
        }

        $Filter = Set-WmiInstance -Class __EventFilter -Namespace "root/subscription" -Arguments $FilterArgs -ErrorAction Stop

        $Base64Script = New-CanaryScript -TemplateName $TemplateName -CanaryUrl $CanaryTokensWebBugURL -ErrorAction Stop

        $ConsumerArgs = @{
            Name                = $ConsumerFilterName
            CommandLineTemplate = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $Base64Script"
        }
        
        $Consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments $ConsumerArgs -ErrorAction Stop

        $FilterToConsumerArgs = @{
            Filter = $Filter;
            Consumer = $Consumer;
        }

        Set-WmiInstance -Namespace 'root/subscription' -Class '__FilterToConsumerBinding' -Arguments $FilterToConsumerArgs -ErrorAction Stop | Out-Null

        Write-Host "[+] WMI Canary alert created! A web request to your canary URL ($CanaryTokensWebBugURL) will be made when the template '$TemplateName' is requested." -ForegroundColor Green
    } catch {
        Write-Host "[!] Creation of WMI subscription failed: $($_.Exception.Message)" -ForegroundColor Red
        Remove-WMISubscription -TemplateName $TemplateName
        throw
    }
}