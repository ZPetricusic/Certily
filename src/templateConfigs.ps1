$TemplateAttributesBase = @{
    <#
    .DESCRIPTION
        Base attributes common to all certificate templates.
    #>
    'msPKI-Template-Minor-Revision' = 1
    'msPKI-Minimal-Key-Size'        = 2048
    'msPKI-Private-Key-Flag'        = 0
    'msPKI-RA-Signature'            = 0
    'pKIDefaultKeySpec'             = 1
    'pKIKeyUsage'                   = ([byte[]](160, 0))
    'pKIMaxIssuingDepth'            = 0
    'pKIOverlapPeriod'              = ([byte[]](0, 128, 166, 10, 255, 222, 255, 255))
    'pKIExpirationPeriod'           = ([byte[]](0, 64, 57, 135, 46, 225, 254, 255))
}

$TemplateAttributesAdditional = @{
    <#
    .DESCRIPTION
        Additional attributes specific to each ESC exploitation type.
        These configurations make templates appear vulnerable to specific attack techniques.
    #>
    "ESC1"  = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_MODIFIED
        'revision'                              = 101
        'pKICriticalExtensions'                 = @('2.5.29.15', '2.5.29.17')
        'pKIDefaultCSPs'                        = '1,Microsoft RSA SChannel Cryptographic Provider'
        'msPKI-Template-Schema-Version'         = 2
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Application-Policy'  = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
    }
    "ESC2"  = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_MODIFIED
        'revision'                              = 101
        'pKICriticalExtensions'                 = @('2.5.29.15', '2.5.29.17')
        'pKIDefaultCSPs'                        = '1,Microsoft RSA SChannel Cryptographic Provider'
        'msPKI-Template-Schema-Version'         = 2
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = '2.5.29.37.0'
        'msPKI-Certificate-Application-Policy'  = '2.5.29.37.0'
    }
    "ESC3"  = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_MODIFIED
        'revision'                              = 101
        'pKICriticalExtensions'                 = @('2.5.29.15', '2.5.29.17')
        'pKIDefaultCSPs'                        = '1,Microsoft RSA SChannel Cryptographic Provider'
        'msPKI-Template-Schema-Version'         = 2
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = '1.3.6.1.4.1.311.20.2.1'
        'msPKI-Certificate-Application-Policy'  = '1.3.6.1.4.1.311.20.2.1'
    }
    "ESC4"  = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_MODIFIED
        'revision'                              = 101
        'pKICriticalExtensions'                 = @('2.5.29.15', '2.5.29.17')
        'pKIDefaultCSPs'                        = '1,Microsoft RSA SChannel Cryptographic Provider'
        'msPKI-Template-Schema-Version'         = 2
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Application-Policy'  = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.3')
    }
    "ESC9"  = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_MODIFIED
        'revision'                              = 101
        'pKICriticalExtensions'                 = @('2.5.29.15', '2.5.29.17')
        'pKIDefaultCSPs'                        = '1,Microsoft RSA SChannel Cryptographic Provider'
        'msPKI-Template-Schema-Version'         = 2
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_NO_SECURITY_EXTENSION -bor
                                                  [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Application-Policy'  = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
    }
    "ESC15" = @{
        'flags'                                 = [GeneralFlags]::CT_FLAG_ADD_EMAIL -bor
                                                  [GeneralFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [GeneralFlags]::CT_FLAG_EXPORTABLE_KEY -bor
                                                  [GeneralFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [GeneralFlags]::CT_FLAG_ADD_TEMPLATE_NAME -bor
                                                  [GeneralFlags]::CT_FLAG_IS_DEFAULT
        'revision'                              = 4
        'pKICriticalExtensions'                 = '2.5.29.15'
        'pKIDefaultCSPs'                        = @(
            '3,Microsoft Base DSS Cryptographic Provider',
            '2,Microsoft Base Cryptographic Provider v1.0',
            '1,Microsoft Enhanced Cryptographic Provider v1.0'
        )
        'msPKI-Template-Schema-Version'         = 1
        'msPKI-Certificate-Name-Flag'           = [CertificateNameFlags]::CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_EMAIL -bor
                                                  [CertificateNameFlags]::CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH
        'msPKI-Enrollment-Flag'                 = [EnrollmentFlags]::CT_FLAG_AUTO_ENROLLMENT -bor
                                                  [EnrollmentFlags]::CT_FLAG_PUBLISH_TO_DS -bor
                                                  [EnrollmentFlags]::CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS
        'pKIExtendedKeyUsage'                   = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.1')
        'msPKI-Certificate-Application-Policy'  = @('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.3')
    }
}

$HidePropertyOptions = @{
    <#
    .DESCRIPTION
        Available protection options for each ESC type.
        Defines which properties can be hidden/protected for each exploitation technique.
    #>
    "ESC1"  = @(
            @{ Key = 1; Property = "RASignature"; Description = "Require authorized signatures (msPKI-RA-Signature)" }
            @{ Key = 2; Property = "CAManagerApproval"; Description = "Require CA manager approval (CT_FLAG_PEND_ALL_REQUESTS)" }
    )
    "ESC2"  = @(
            @{ Key = 1; Property = "RASignature"; Description = "Require authorized signatures (msPKI-RA-Signature)" }
            @{ Key = 2; Property = "CAManagerApproval"; Description = "Require CA manager approval (CT_FLAG_PEND_ALL_REQUESTS)" }
    )
    "ESC3"  = @(
            @{ Key = 1; Property = "RASignature"; Description = "Require authorized signatures (msPKI-RA-Signature)" }
            @{ Key = 2; Property = "CAManagerApproval"; Description = "Require CA manager approval (CT_FLAG_PEND_ALL_REQUESTS)" }
    )
    "ESC4"  = @(
            @{ Key = 1; Property = "RASignature"; Description = "Require authorized signatures (msPKI-RA-Signature)" }
            @{ Key = 2; Property = "CAManagerApproval"; Description = "Require CA manager approval (CT_FLAG_PEND_ALL_REQUESTS)" }
    )
    "ESC9"  = @(
            @{ Key = 1; Property = "RASignature"; Description = "Require authorized signatures (msPKI-RA-Signature)" }
    )
    "ESC15" = @(
            @{ Key = 1; Property = "CAManagerApproval"; Description = "Require CA manager approval (CT_FLAG_PEND_ALL_REQUESTS)" }
    )
}