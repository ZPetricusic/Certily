function Set-DeterministicDCandDrive {
    <#
    .SYNOPSIS
    Locks all Active Directory operations to a single domain controller for session consistency.
    
    .DESCRIPTION
    Retrieves the current logon domain controller and configures the PowerShell session to use 
    that specific DC for all subsequent AD operations. This includes mounting an AD PowerShell 
    drive and setting default parameter values to prevent replication inconsistencies.
    
    .EXAMPLE
    Set-DeterministicDCandDrive
    
    Configures the session to use the current logon DC for all AD cmdlets and mounts the AD drive.
    
    .NOTES
    Requires the Active Directory PowerShell module and the New-ADPSDriveItem helper function.
    This function modifies $PSDefaultParameterValues for the current session.
    #>
    # Get current logon DC and mount AD drive to its root
    $dc = Get-ADDomainController | Select-Object -ExpandProperty HostName
    # deterministically mount the AD drive
    New-ADPSDriveItem -DomainController $dc
    # set up the default -Server value for AD-related commands
    $PSDefaultParameterValues['*-AD*:Server'] = $dc
}

function Test-IfAdmin {
    <#
    .SYNOPSIS
        Checks whether the script is running under Administrative context.

    .DESCRIPTION
        Checks whether the script is running under Administrative context,
        since the local audit policy is being changed to ensure that ADCS
        logging is enabled.
    #>
    return ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TemplatePath {
    <#
    .SYNOPSIS
        Retrieves the Distinguished Name path to the Certificate Templates container.
    
    .DESCRIPTION
        Queries Active Directory to get the configuration naming context and constructs
        the full path to where certificate templates are stored.
    
    .OUTPUTS
        System.String - The full DN path to the Certificate Templates container
    
    .EXAMPLE
        $templatePath = Get-TemplatePath
    #>
    try {
        $ConfigNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        return "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
    }
    catch {
        Write-Host -ForegroundColor Red "[!] Error while retrieving ADCS template path: $($_.Exception.Message)"
        throw
    }
}

function Get-PKIServerDN {
    <#
    .SYNOPSIS
        Retrieves the Distinguished Name path to the Certificate Services server..
    
    .DESCRIPTION
        Queries Active Directory to get the configuration naming context and constructs
        the full path to the current ADCS server.
    
    .OUTPUTS
        System.String - The full DN path to the Certificate Services server
    
    .EXAMPLE
        $AdcsDN = Get-PKIServerDN
    #>
    try {
        $ConfigNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $CAName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction Stop | Select-Object -ExpandProperty Active
        return "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
    }
    catch {
        Write-Host -ForegroundColor Red "[!] Error while retrieving ADCS DN: $($_.Exception.Message)"
        throw
    }
}

function New-CertilyTemplateOID {
    <#
    .SYNOPSIS
        Generates a unique Object Identifier (OID) for a new certificate template.
    
    .DESCRIPTION
        Creates a new OID by parsing existing template OIDs, extracting the base OID,
        and appending two random 8-digit numbers to ensure uniqueness.
    
    .OUTPUTS
        System.String - A unique OID string for the new template
    
    .EXAMPLE
        $newOID = New-CertilyTemplateOID
    #>
    try {
        $TemplatePath = Get-TemplatePath

        $ExistingOIDs = Get-ADObject -SearchBase $TemplatePath -Filter * `
            -Properties 'msPKI-Cert-Template-OID' -ErrorAction Stop |
            Select-Object -ExpandProperty 'msPKI-Cert-Template-OID'

        $FirstOID = $ExistingOIDs | Select-Object -First 1

        if ($FirstOID -match '^((?:\d+\.)+\d+)\.\d+\.\d+$') {
            $BaseOID = $Matches[1]
        }
        else {
            Write-Host -ForegroundColor Red "[!] Failed to parse base OID from existing templates"
            throw
        }

        $Random1 = Get-Random -Minimum 10000000 -Maximum 99999999
        $Random2 = Get-Random -Minimum 10000000 -Maximum 99999999

        $NewOID = "$BaseOID.$Random1.$Random2"

        return $NewOID
    }
    catch {
        Write-Host -ForegroundColor Red "[!] Failed to generate OID: $($_.Exception.Message)"
        throw
    }
}

function Show-TemplateHelp {
    <#
    .SYNOPSIS
        Displays comprehensive usage help for the Certily module.
    
    .DESCRIPTION
        Shows available ESC types, parameters, examples, and prerequisites for creating
        honeypot certificate templates.
    #>
    Write-Host -ForegroundColor Cyan @"

_________                __  .__.__         
\_   ___ \  ____________/  |_|__|  | ___.__.
/    \  \/_/ __ \_  __ \   __\  |  |<   |  |
\     \___\  ___/|  | \/|  | |  |  |_\___  |
 \______  /\___  >__|   |__| |__|____/ ____|
        \/     \/                    \/     

The ADCS Honeypot Template Creator

Usage:
    New-CertilyTemplate -TemplateName "SomeTemplateName" -ESCType "ESC1" [-UseCanaryTokens]

Parameters:
    -TemplateName    Name for your certificate template (required)
    -ESCType         Type of ESC configuration (required)
    -UseCanaryTokens Whether or not a Canary Token should be triggered through a WMI event subscription

Usage:
    Remove-CertilyTemplate -TemplateName "SomeExistingTemplateName" [-RemoveCanaryToken]

Parameters:
    -TemplateName       Name for your certificate template (required)
    -RemoveCanaryToken  If a Canary Token trigger was created for this template, the WMI subscription will be removed


Available ESC types:
    ESC1   - Client authentication with user-controlled SAN
    ESC2   - Any Purpose EKU template
    ESC3   - Certificate Request Agent EKU present
    ESC4   - Vulnerable ACL allowing template modification
    ESC9   - StrongCertificateBindingEnforcement = 0 (NO_SECURITY_EXTENSION)
    ESC15  - Legacy schema version 1 template

Examples:
    New-CertilyTemplate -TemplateName "ESC1-Test" -ESCType "ESC1" -UseCanaryTokens
    New-CertilyTemplate -TemplateName "TotallyLegitTemplate" -ESCType "ESC2"
    New-CertilyTemplate -TemplateName "CertificateRequestAgent" -ESCType "ESC3" -UseCanaryTokens
    New-CertilyTemplate -TemplateName "ESC4-Test" -ESCType "ESC4"
    New-CertilyTemplate -TemplateName "Cert4NDES" -ESCType "ESC9" -UseCanaryTokens
    New-CertilyTemplate -TemplateName "ESC15-Test" -ESCType "ESC15"

    Remove-CertilyTemplate -TemplateName "ESC1-Test" -RemoveCanaryToken

Prerequisites:
    - Domain/Enterprise Admin privileges
    - ADCS installed and configured
    - ActiveDirectory PowerShell module
    - ADCSAdministration PowerShell module
"@
}

function Get-HidePropertyChoice {
    <#
    .SYNOPSIS
        Prompts the user to select which property to protect and hide.
    
    .DESCRIPTION
        Displays available protection options for the specified ESC type and prompts
        the user to select one. ESC9 automatically uses CAManagerApproval.
    
    .PARAMETER ESCType
        The type of ESC vulnerability being simulated
    
    .OUTPUTS
        System.String - The selected property name to protect
    
    .EXAMPLE
        $property = Get-HidePropertyChoice -ESCType "ESC1"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ESCType
    )

    $options = $HidePropertyOptions[$ESCType]

    if ($ESCType -eq "ESC9" -or $ESCType -eq "ESC15") {
        Write-Host "`n[*] $ESCType automatically uses: $($options[0].Description)" -ForegroundColor Cyan
        return $options[0].Property
    }

    while ($true) {
        Write-Host "`n--------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "  Select Property to Protect and Hide" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------`n" -ForegroundColor Cyan

        foreach ($option in $options) {
            Write-Host "  $($option.Key) - $($option.Description)" -ForegroundColor White
        }

        $choice = Read-Host "`nEnter choice (1-$($options.Count))"

        $selectedOption = $options | Where-Object { $_.Key -eq $choice }

        if ($selectedOption) {
            Write-Host "[+] Selected: $($selectedOption.Description)" -ForegroundColor Green
            return $selectedOption.Property
        }
        else {
            Write-Host "[!] Invalid choice '$choice'. Please select a valid option (1-$($options.Count))" -ForegroundColor Red
        }
    }
}

function New-ADPSDriveItem {
    <#
    .SYNOPSIS
        Ensures that a deterministically chosen AD: PSDrive exists.
    
    .DESCRIPTION
        The function checks if the AD: PSDrive exists, which it should if
        the ActiveDirectory Powershell module was successfully imported.
        If the drive exists, it is removed and replaced with an AD PSDrive
        "mounted" from the primary domain controller. This ensures that
        all directory objects are created and read from the same domain
        controller, preventing any synchronization issues which may cause
        non-deterministic script errors.
    
    .PARAMETER DomainController
        The domain controller to use for mounting the AD PSDrive.
    
    .OUTPUTS
        Returns the FQDN of the domain controller which was chosen to mount the AD drive.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$DomainController
    )

    # Remove existing AD: drive if present
    if (Get-PSDrive -Name AD -Scope Script -ErrorAction SilentlyContinue) {
        Write-Host "[*] Removing the AD drive from the scope of this script" -ForegroundColor Yellow
        Remove-PSDrive -Name AD -Scope Script -ErrorAction Stop
    }

    Write-Host "[*] Mounting AD drive for the script to the '$DomainController' DC" -ForegroundColor Yellow
    New-PSDrive -PSProvider ActiveDirectory -Name AD -Root "//RootDSE/" -Server $DomainController -ErrorAction Stop -Scope Script | Out-Null
    Write-Host "[+] AD drive mounted!" -ForegroundColor Green
}