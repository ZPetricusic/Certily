function Set-TemplateACL {
    <#
    .SYNOPSIS
        Configures initial ACL permissions for template enrollment.
    
    .DESCRIPTION
        Sets up Read and Enroll permissions for Everyone (for most ESC types) or
        Read and GenericWrite permissions (for ESC4). These permissions make the
        template appear vulnerable to attackers.
    
    .PARAMETER TemplateDN
        The Distinguished Name of the certificate template
    
    .PARAMETER ESCType
        The type of ESC vulnerability being simulated
    
    .EXAMPLE
        Set-TemplateACL -TemplateDN "CN=MyTemplate,..." -ESCType "ESC1"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateDN,

        [Parameter(Mandatory = $true)]
        [ValidateSet("ESC1", "ESC2", "ESC3", "ESC4", "ESC9", "ESC15")]
        [string]$ESCType
    )

    try {
        $ACL = Get-Acl -Path "AD:$TemplateDN" -ErrorAction Stop

        # Grant Read permissions to Everyone
        $ReadRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $DomainUsersIdentity,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $ACL.AddAccessRule($ReadRule)

        if ($ESCType -eq "ESC4") {
            # ESC4: Grant GenericWrite to make template modifiable
            $WriteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $DomainUsersIdentity,
                [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $ACL.AddAccessRule($WriteRule)
            Write-Host "[+] Added Read and GenericWrite permissions for 'Domain Users'" -ForegroundColor Green
        }
        else {
            # Other ESC types: Grant Enroll extended right
            $EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $DomainUsersIdentity,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $EnrollGUID
            )
            $ACL.AddAccessRule($EnrollRule)
            Write-Host "[+] Added Read and Enroll permissions for 'Domain Users'" -ForegroundColor Green
        }

        Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL -ErrorAction Stop
        Write-Host "[+] Permissions applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to set ACL: $($_.Exception.Message)"
        throw
    }
}

function Set-PropertyProtection {
    <#
    .SYNOPSIS
        Modifies template properties to add protection mechanisms.
    
    .DESCRIPTION
        Changes specific template properties to secure values to mimic
        the vulnerable version. This creates a deceptive layer where the CA appears
        to be serving vulnerable certificates which cannot be exploited.
    
    .PARAMETER TemplateDN
        The Distinguished Name of the certificate template
    
    .PARAMETER HideProperty
        Which property to modify (TemplateSchema, RASignature, or CAManagerApproval)
    
    .EXAMPLE
        Set-PropertyProtection -TemplateDN "CN=MyTemplate,..." -HideProperty "RASignature"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateDN,

        [Parameter(Mandatory = $true)]
        [string]$HideProperty
    )

    try {
        $HidePropertyName = $PropertyMap[$HideProperty]["name"]

        Write-Host "`n--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "  Modifying Template Properties (Adding Protection)" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------------`n" -ForegroundColor Yellow

        switch ($HideProperty) {
            "RASignature" {
                Set-ADObject -Identity $TemplateDN -Replace @{'msPKI-RA-Signature' = 1 } -ErrorAction Stop
                Write-Host "[+] Changed: msPKI-RA-Signature = 0 -> 1 (Requires authorized signatures)" -ForegroundColor Yellow
            }
            "CAManagerApproval" {
                $currentFlag = Get-ADObject -Identity $TemplateDN -Properties 'msPKI-Enrollment-Flag' -ErrorAction Stop | `
                               Select-Object -ExpandProperty 'msPKI-Enrollment-Flag'
                $newFlag = $currentFlag -bor [EnrollmentFlags]::CT_FLAG_PEND_ALL_REQUESTS
                Set-ADObject -Identity $TemplateDN -Replace @{'msPKI-Enrollment-Flag' = $newFlag } -ErrorAction Stop
                Write-Host "[+] Added: CT_FLAG_PEND_ALL_REQUESTS (0x2) - CA Manager Approval Required" -ForegroundColor Yellow
            }
            # "TemplateSchema" {
            #     Set-ADObject -Identity $TemplateDN -Replace @{'msPKI-Template-Schema-Version' = 2 } -ErrorAction Stop
            #     Write-Host "[+] Changed: msPKI-Template-Schema-Version = 1 -> 2 (Updated to newer schema)" -ForegroundColor Yellow
            # }
        }

        Write-Host "[+] Property '$HidePropertyName' modified to safe value" -ForegroundColor Green
        Write-Host "[*] CA is now serving a secure, but vulnerable-looking template" -ForegroundColor Cyan

    }
    catch {
        Write-Host "[!] ERROR: Failed to modify property: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Set-ESC4Protection {
    <#
    .SYNOPSIS
        Applies Deny Write ACLs to ESC4 template properties.
    
    .DESCRIPTION
        Protects ESC4 templates by applying Deny Write permissions on critical properties
        (Certificate-Name-Flag, Enrollment-Flag, ExtendedKeyUsage) to prevent tampering
        with the template configuration.
    
    .PARAMETER TemplateDN
        The Distinguished Name of the certificate template
    
    .EXAMPLE
        Set-ESC4Protection -TemplateDN "CN=MyTemplate,..."
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateDN
    )

    try {
        Write-Host "`n--------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "  Protecting ESC4 Properties (Applying Deny Write)" -ForegroundColor Yellow
        Write-Host "--------------------------------------------------------`n" -ForegroundColor Yellow

        $ACL = Get-Acl -Path "AD:$TemplateDN" -ErrorAction Stop

        Write-Host "[*] Applying Deny WRITE on 3 critical properties..." -ForegroundColor Yellow

        foreach ($guid in $ESC4GUIDs) {
            $DenyWriteRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $DomainUsersIdentity,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Deny,
                $guid
            )
            $ACL.AddAccessRule($DenyWriteRule)
        }

        Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL -ErrorAction Stop

        Write-Host "[+] Deny Write ACLs applied - properties protected from modification" -ForegroundColor Green
        Write-Host "[*] CA is now serving a secure, but vulnerable-looking template" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[!] ERROR: Failed to apply Deny Write ACLs: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Set-ESC4FailureSACL {
    <#
    .SYNOPSIS
        Sets a SACL to enable interaction monitoring with the ESC4 template.
    
    .DESCRIPTION
        Creates a SACL for monitoring Domain Users' write-failure events
        related to the ESC4 template. The SACL is explicitly set on an AD object
        and should therefore be monitored via the Directory Services Access event ID 4662.
        Although ADCS events exist related to template modifications, these events are only
        fired if the template is also requested/enrolled, making them unfeasible
        for the purposes of a honeypot.
    
    .LINK
        https://www.beyondtrust.com/blog/entry/esc4-attacks
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786432(v=ws.11)#monitoring-changes-to-certificate-templates
    
    .PARAMETER TemplateDN
        The DN (path) of the template being monitored.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateDN
    )

    $writeRights = @(
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
    )

    try {
        Write-Host "[*] Setting a Failure SACL on '$TemplateDN', monitoring for Domain Users activity" -ForegroundColor Yellow

        $templateAcl = Get-Acl -Audit -Path "AD:$TemplateDN" -ErrorAction Stop
        
        foreach ($right in $writeRights) {
            $FailedAccessRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                $DomainUsersIdentity,
                $right,
                [System.Security.AccessControl.AuditFlags]::Failure
            )
            $templateAcl.AddAuditRule($FailedAccessRule)
        }

        Set-Acl -Path "AD:$TemplateDN" -AclObject $templateAcl -ErrorAction Stop

        Write-Host "[+] ESC4 SACL successfully set!" -ForegroundColor Green
        Write-Host "[*] Please note that this event will not trigger unless the Directory Services Access auditing policy is enabled for Failure events (EID 4662/F)." -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Error while setting ESC4 SACL: $($_.Exception.Message)"
        throw
    }
}

function Hide-Properties {
    param(
        <#
        .SYNOPSIS
            Hides template properties from enumeration using Deny Read ACLs.
        
        .DESCRIPTION
            Applies Deny Read permissions to protection properties, making them invisible
            to attackers during enumeration. This ensures attackers cannot see the
            protective mechanisms that have been applied.
        
        .PARAMETER TemplateDN
            The Distinguished Name of the certificate template
        
        .PARAMETER HideProperty
            Which property to hide (TemplateSchema, RASignature, or CAManagerApproval)
        
        .PARAMETER ESCType
            The type of ESC vulnerability being simulated
        
        .EXAMPLE
            Hide-Properties -TemplateDN "CN=MyTemplate,..." -HideProperty "RASignature" -ESCType "ESC1"
        #>
        [Parameter(Mandatory = $true)]
        [string]$TemplateDN,

        [Parameter(Mandatory = $false)]
        [ValidateSet("TemplateSchema", "RASignature", "CAManagerApproval")]
        [string]$HideProperty,

        [Parameter(Mandatory = $true)]
        [ValidateSet("ESC1", "ESC2", "ESC3", "ESC4", "ESC9", "ESC15")]
        [string]$ESCType
    )

    try {
        Write-Host "`n--------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "  Hiding Properties (Applying Deny Read)" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------`n" -ForegroundColor Cyan

        $ACL = Get-Acl -Path "AD:$TemplateDN" -ErrorAction Stop

        if ($ESCType -eq "ESC4") {
            Write-Host "[*] Applying Deny READ on 3 ESC4 properties..." -ForegroundColor Yellow

            foreach ($guid in $ESC4GUIDs) {
                $DenyReadRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $DomainUsersIdentity,
                    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
                    [System.Security.AccessControl.AccessControlType]::Deny,
                    $guid
                )
                $ACL.AddAccessRule($DenyReadRule)
            }

            Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL -ErrorAction Stop
            Write-Host "[+] All 3 properties are now hidden from 'Domain Users'" -ForegroundColor Green
        }

        $HidePropertyName = $PropertyMap[$HideProperty]["name"]
        $HidePropertyGUID = $PropertyMap[$HideProperty]["guid"]

        Write-Host "[*] Applying Deny READ on property: $HidePropertyName" -ForegroundColor Yellow

        $DenyReadRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $DomainUsersIdentity,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
            [System.Security.AccessControl.AccessControlType]::Deny,
            $HidePropertyGUID
        )
        $ACL.AddAccessRule($DenyReadRule)

        Set-Acl -Path "AD:$TemplateDN" -AclObject $ACL -ErrorAction Stop
        Write-Host "[+] Property '$HidePropertyName' is now hidden from 'Domain Users'" -ForegroundColor Green
        
        Write-Host "[+] Attackers cannot see the protection mechanisms during enumeration" -ForegroundColor Green

    }
    catch {
        Write-Host "[!] ERROR: Failed to hide properties: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}