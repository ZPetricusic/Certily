@{
	RootModule = 'Certily.psm1'
	Author = 'Josip Pavicic (Infigo IS) & Zdravko Petricusic (Span)'
	ModuleVersion = '0.2.0'
	Description = '
This module creates honeypot certificate templates in Active Directory that appear
vulnerable to various ADCS exploitation techniques (ESC1, ESC2, ESC3, ESC4, ESC9, ESC15),
but are actually protected through hidden security configurations.

Purpose: Create deceptive certificate templates that:
    - Appear vulnerable to attackers during enumeration
    - Have hidden protections that prevent actual exploitation
    - Help detect and alert on ADCS-based attacks

Requirements:
    - Domain/Enterprise Admin privileges
    - Active Directory Certificate Services (ADCS) installed and configured
    - ActiveDirectory and ADCSAdministration PowerShell modules'

	RequiredModules = @("ActiveDirectory", "ADCSAdministration")
	NestedModules = @(
        './src/ACL.ps1',
        './src/canary.ps1',
        './src/constants.ps1'
        './src/newTemplate.ps1',
        './src/removeTemplate.ps1',
        './src/templateConfigs.ps1',
        './src/utils.ps1'
    )
	FunctionsToExport = @(
        "New-CertilyTemplate",
        "Remove-CertilyTemplate"
    )

    PrivateData = @{
		PSData = @{
			Tags = @('ActiveDirectory', 'AD', 'ActiveDirectoryCertificateServices', 'ADCS', 'Honeypot', 'ESC1')
			LicenseUri = 'https://github.com/ZPetricusic/Certily/blob/main/LICENSE'
			ProjectURI = 'https://github.com/ZPetricusic/Certily'
			IconUri = 'TBD'
		}
	}

	HelpInfoURI = 'https://github.com/ZPetricusic/Certily/blob/main/README.md'
	DefaultCommandPrefix = ''
}
