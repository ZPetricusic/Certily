function Remove-CertilyTemplate {
    <#
    .SYNOPSIS
        Cleanup function for removing a honeypot template and the optional Canary Token WMI trigger.
    
    .DESCRIPTION
        This function removes the previously created Certily template from Active Directory,
        prompting the user to confirm the object deletion before the action takes place.
        Additionally, if any Canary Tokens were added for the template, this function can
        remove the related WMI subscription used to trigger Canary alerts.
    
    .PARAMETER TemplateName
        The name for the new certificate template
    
    .PARAMETER UseCanaryTokens
        Whether or not to remove a WMI event subscription created for the template 
    
    .EXAMPLE
        Remove-CertilyTemplate -TemplateName "ESC1-Honeypot" -RemoveCanaryToken
    
    .NOTES
        This function requires Domain/Enterprise Admin privileges and a configured
        Active Directory Certificate Services environment. Additionally, this function
        can be used to remove *ANY* template from AD - ensure you're selecting the right one.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveCanaryToken = $false
    )

    try {
        Set-DeterministicDCandDrive

        $TemplatePath = Get-TemplatePath
        $TemplateDN = "CN=$TemplateName,$TemplatePath"

        Write-Host "[*] Unpublishing the template '$TemplateName' from the CA..." -ForegroundColor Cyan
        Remove-CATemplate -Name $TemplateName -ErrorAction Stop -Confirm

        $template = Get-ADObject -Properties * -Filter "cn -eq '$TemplateName'" -SearchBase $TemplatePath -ErrorAction Stop
        Write-Warning "[*] You have selected the template '$TemplateName' for deletion, please verify the template data below:"
        $template | Format-List *

        # prompt before deletion
        Remove-ADObject -Confirm -Identity $TemplateDN -ErrorAction Stop

        Write-Host "[+] Successfully removed template '$TemplateName' from Active Directory!" -ForegroundColor Green

        if ($RemoveCanaryToken) {
            Remove-WMISubscription -TemplateName $TemplateName
        } else {
            Remove-WMISubscription -TemplateName $TemplateName -CheckOnly
        }
    } catch {
        Write-Host "[!] Error while cleaning up Certily template artifacts: $($_.Exception.Message)" -ForegroundColor Red
    }
}