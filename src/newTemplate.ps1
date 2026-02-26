function New-CertilyTemplate {
    <#
    .SYNOPSIS
        Creates a honeypot certificate template vulnerable to specified ADCS exploitation.
    
    .DESCRIPTION
        This function creates a certificate template that appears vulnerable to various
        ADCS exploitation techniques (ESC1, ESC2, ESC4, ESC9, ESC15) but has hidden
        protections that prevent actual exploitation. The CA appears to be serving the vulnerable
        configuration, but Active Directory contains protective settings that are
        hidden from attackers via Deny Read ACLs.
    
        The function performs the following steps:
        1. Creates the template with vulnerable configuration in AD
        2. Sets initial ACLs (Read + Enroll or Read + GenericWrite)
        3. Publishes the template to the CA
        4. Applies protection mechanisms (property changes or Deny Write ACLs)
        5. Hides protection properties using Deny Read ACLs
    
    .PARAMETER TemplateName
        The name for the new certificate template
    
    .PARAMETER ESCType
        The type of ESC vulnerability to simulate (ESC1, ESC2, ESC3, ESC4, ESC9, or ESC15)
    
    .PARAMETER UseCanaryTokens
        Whether or not to configure a WMI event subscription, 
        triggering a Canary Token alert when a honeypot template is requested.
    
    .EXAMPLE
        New-CertilyTemplate -TemplateName "ESC1-Honeypot" -ESCType "ESC1"
    
    .EXAMPLE
        New-CertilyTemplate -TemplateName "Cert4NDES" -ESCType "ESC2" -UseCanaryTokens
    
    .NOTES
        This function requires Domain/Enterprise Admin privileges and a configured
        Active Directory Certificate Services environment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("ESC1", "ESC2", "ESC3", "ESC4", "ESC9", "ESC15")]
        [string]$ESCType,

        [Parameter(Mandatory = $false)]
        [switch]$UseCanaryTokens = $false
    )

    # Get template path and construct DN
    $TemplatePath = Get-TemplatePath
    $TemplateDN = "CN=$TemplateName,$TemplatePath"

    Set-DeterministicDCandDrive

    # Check if template already exists
    if (Get-ADObject -Filter "cn -eq '$TemplateName'" -SearchBase $TemplatePath -ErrorAction SilentlyContinue) {
        Write-Host "[!] Template '$TemplateName' already exists!" -ForegroundColor Red
        Write-Host "[!] Run `"Remove-CATemplate -Name '$TemplateName'; Remove-ADObject -Server '$(Get-ADDomainController | Select-Object -ExpandProperty HostName)'-Identity '$TemplateDN' -Confirm`" to delete the template." -ForegroundColor Red
        return
    }

    if (Test-IfAdmin) {
        Set-AuditingPolicy
    } else {
        throw "Administrative privileges not found, exiting"
    }

    if ($UseCanaryTokens) {
        if ($ESCType -eq "ESC4") {
            Write-Warning "Canary events are not available for ESC4, skipping"
        } else {
            Write-Host "[*] Setting up Canary Token alerting via WMI" -ForegroundColor Cyan
            Write-Warning "Please note that WMI alerting is not the most reliable - event logs should instead be collected and ingested into a SIEM for more reliable detections."
            Set-CanaryTokenAlert -TemplateName $TemplateName
        }
    }

    if ($ESCType -eq "ESC3") {
        Write-Warning "While deploying an ESC3 honeypot template is supported, such templates are not frequently found in ADCS environments. Consider deploying a more common template, such as ESC1."
        Read-Host "Press [Return] to continue"
    }

    try {
        Write-Host "`n----------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host " Creating $ESCType Honeypot Template: $TemplateName" -ForegroundColor Cyan 
        Write-Host "----------------------------------------------------------------------------`n" -ForegroundColor Cyan

        # Generate unique OID for template
        $NewOID = New-CertilyTemplateOID
        Write-Host "[+] Generated OID: $NewOID" -ForegroundColor Green

        # STEP 1: Create template in AD with vulnerable configuration
        Write-Host "`n[*] Step 1: Creating template object in Active Directory..." -ForegroundColor Yellow

        $AllAttributes = $TemplateAttributesBase.Clone()
        foreach ($key in $TemplateAttributesAdditional[$ESCType].Keys) {
            $AllAttributes[$key] = $TemplateAttributesAdditional[$ESCType][$key]
        }

        $AllAttributes['displayName'] = $TemplateName
        $AllAttributes['name'] = $TemplateName
        $AllAttributes['msPKI-Cert-Template-OID'] = $NewOID
        $AllAttributes['objectClass'] = 'pKICertificateTemplate'

        New-ADObject -Name $TemplateName -Type pKICertificateTemplate `
            -Path $TemplatePath -OtherAttributes $AllAttributes -ErrorAction Stop
        Write-Host "[+] Template object created in AD (VULNERABLE configuration)" -ForegroundColor Green

        # STEP 2: Set initial ACLs
        Write-Host "`n[*] Step 2: Configuring initial ACL permissions..." -ForegroundColor Yellow
        Set-TemplateACL -TemplateDN $TemplateDN -ESCType $ESCType

        # STEP 3: Publish template to CA
        Write-Host "`n[*] Step 3: Publishing template to Certificate Authority..." -ForegroundColor Yellow

        # $currentTemplates = certutil.exe -CATemplates | Where-Object { $_ -match '^(.+):.+\-\-' } | ForEach-Object {
        #     if ($_ -match '^(.+):.+\-\-') { $matches[1] }
        # }

        [string[]]$currentTemplates = Get-CATemplate | Select-Object -ExpandProperty Name

        $CAServer = Get-PKIServerDN

        if ($currentTemplates) {
            $allTemplates = $currentTemplates + $TemplateName
            Set-ADObject -Identity $CAServer -Add @{ certificateTemplates = $allTemplates } -ErrorAction Stop
        }
        else {
            Set-ADObject -Identity $CAServer -Add @{ certificateTemplates = $TemplateName } -ErrorAction Stop
        }
        
        # Verify template was published
        if (Get-CATemplate | Where-Object {$_.Name -eq "$TemplateName"}) {
            Write-Host "[+] Template published to CA successfully" -ForegroundColor Green
        }
        else {
            Write-Host "[!] Template was not be published correctly! List of published templates is below:" -ForegroundColor Red
            Get-CATemplate | Format-List -Property Name
            throw "Template was not published correctly!"
        }
        
        # Write-Host "[*] Current Templates:" -ForegroundColor Yellow
        # Get-CATemplate | Format-List -Property Name

        # Modify properties to safe values
        $HideProperty = Get-HidePropertyChoice -ESCType $ESCType
        Set-PropertyProtection -TemplateDN $TemplateDN -HideProperty $HideProperty

        # STEP 5: Hide properties with Deny Read ACLs
        Write-Host "`n[*] Step 4: Hiding protection properties from enumeration..." -ForegroundColor Yellow

        Hide-Properties -TemplateDN $TemplateDN -HideProperty $HideProperty -ESCType $ESCType

        # STEP 4: Apply protection mechanisms
        Write-Host "`n[*] Step 5: Applying protection mechanisms..." -ForegroundColor Yellow

        if ($ESCType -eq "ESC4") {
            # ESC4: Apply Deny Write ACLs on critical properties
            Set-ESC4Protection -TemplateDN $TemplateDN
            # Apply a SACL to monitor for failure events againts the template
            Set-ESC4FailureSACL -TemplateDN $TemplateDN
        }
        
        # Display final summary
        Write-Host "`n|----------------------------------------------------------------------------|" -ForegroundColor Green
        Write-Host "|                    Honeypot Deployment Complete!                           |" -ForegroundColor Green
        Write-Host "|----------------------------------------------------------------------------|" -ForegroundColor Green

        Write-Host "`nTemplate Details:" -ForegroundColor White
        Write-Host "  Name:     $TemplateName" -ForegroundColor White
        Write-Host "  Type:     $ESCType" -ForegroundColor White
        Write-Host "  OID:      $NewOID" -ForegroundColor White
        Write-Host "  Location: $TemplateDN" -ForegroundColor White

        Write-Host "`nProtection Status:" -ForegroundColor White
        if ($ESCType -eq "ESC4") {
            Write-Host "  [+] ESC4 properties PROTECTED (Deny Write on 3 properties)" -ForegroundColor Green
            Write-Host "  [+] ESC4 properties HIDDEN (Deny Read on 3 properties)" -ForegroundColor Green
        }

        Write-Host "  [+] Protection property modified to safe value" -ForegroundColor Green
        Write-Host "  [+] Protection property HIDDEN (Deny Read)" -ForegroundColor Green

        Write-Host "`nHoneypot Characteristics:" -ForegroundColor White
        Write-Host "  [+] Attackers see CA serving vulnerable template" -ForegroundColor Green
        Write-Host "  [+] Protection mechanisms invisible to enumeration" -ForegroundColor Green
        Write-Host "  [+] Exploitation attempts will fail (and trigger alerts)" -ForegroundColor Green

    }
    catch {
        Write-Error "Failed to create template: $($_.Exception.Message)"

        Write-Host "`n[!] Attempting template cleanup..." -ForegroundColor Yellow
        try {
            # Remove template from CA if it was published
            if ($currentTemplates) {
                $cleanTemplates = $currentTemplates -join ','
                certutil.exe -SetCATemplates $cleanTemplates | Out-Null
            }

            # Remove AD object if it was created
            Remove-ADObject -Identity $TemplateDN -Confirm:$false -ErrorAction Stop
            Write-Host "[+] Template cleanup completed" -ForegroundColor Green

            if ($UseCanaryTokens){ Remove-WMISubscription -TemplateName $TemplateName }
        }
        catch {
            Write-Host "[!] Cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}