enum EnrollmentFlags {
    <#
    .DESCRIPTION
        Certificate enrollment flags that control template behavior and security settings.
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
    #>
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS                                   = 0x00000001
    CT_FLAG_PEND_ALL_REQUESTS                                              = 0x00000002
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER                                       = 0x00000004
    CT_FLAG_PUBLISH_TO_DS                                                  = 0x00000008
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE                      = 0x00000010
    CT_FLAG_AUTO_ENROLLMENT                                                = 0x00000020
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT                        = 0x00000040
    CT_FLAG_USER_INTERACTION_REQUIRED                                      = 0x00000100
    CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE                 = 0x00000400
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF                                      = 0x00000800
    CT_FLAG_ADD_OCSP_NOCHECK                                               = 0x00001000
    CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL               = 0x00002000
    CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS                                  = 0x00004000
    CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS                         = 0x00008000
    CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT  = 0x00010000
    CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST                                 = 0x00020000
    CT_FLAG_SKIP_AUTO_RENEWAL                                              = 0x00040000
    CT_FLAG_NO_SECURITY_EXTENSION                                          = 0x00080000
}

enum GeneralFlags {
    <#
    .DESCRIPTION
        General certificate template flags that control overall template characteristics.
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0
    #>
    CT_FLAG_ADD_EMAIL            = 0x00000002
    CT_FLAG_PUBLISH_TO_DS        = 0x00000008
    CT_FLAG_EXPORTABLE_KEY       = 0x00000010
    CT_FLAG_AUTO_ENROLLMENT      = 0x00000020
    CT_FLAG_MACHINE_TYPE         = 0x00000040
    CT_FLAG_IS_CA                = 0x00000080
    CT_FLAG_ADD_TEMPLATE_NAME    = 0x00000200
    CT_FLAG_IS_CROSS_CA          = 0x00000800
    CT_FLAG_DONOTPERSISTINDB     = 0x00001000
    CT_FLAG_IS_DEFAULT           = 0x00010000
    CT_FLAG_IS_MODIFIED          = 0x00020000
}

enum CertificateNameFlags {
    <#
    .DESCRIPTION
        Subject name flags used to instruct the requestor on what fields to populate.
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
    #>
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT           = 0x00000001
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME  = 0x00010000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS      = 0x00400000
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN             = 0x00800000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID  = 0x01000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN             = 0x02000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL           = 0x04000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS             = 0x08000000
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN           = 0x10000000
    CT_FLAG_SUBJECT_REQUIRE_EMAIL               = 0x20000000
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME         = 0x40000000
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH      = 0x80000000
}

$ESC4GUIDs = @(
    <#
    .DESCRIPTION
        GUIDs for ESC4-related properties that should be protected from modification.
    #>
    [GUID]'ea1dddc4-60ff-416e-8cc0-17cee534bce7'  # msPKI-Certificate-Name-Flag
    [GUID]'d15ef7d8-f226-46db-ae79-b34e560bd12c'  # msPKI-Enrollment-Flag
    [GUID]'18976af6-3b9e-11d2-90cc-00c04fd91ab1'  # pkiExtendedKeyUsage
)

$PropertyMap = @{
    <#
    .DESCRIPTION
        Mapping of property names to their AD attribute names and GUIDs.
        Used for applying targeted ACL protections on specific properties.
    #>
    # we can't hide the Template Schema, otherwise the CA also sees it as v1,
    # actually making it vulnerable :(
    # 'TemplateSchema'    = @{
    #     "name" = 'msPKI-Template-Schema-Version'
    #     "guid" = [GUID]'0c15e9f5-491d-4594-918f-32813a091da9'
    # }
    'RASignature'       = @{
        "name" = 'msPKI-RA-Signature'
        "guid" = [GUID]'fe17e04b-937d-4f7e-8e0e-9292c8d5683e'
    }
    'CAManagerApproval' = @{
        "name" = 'msPKI-Enrollment-Flag'
        "guid" = [GUID]'d15ef7d8-f226-46db-ae79-b34e560bd12c'
    }
}

#Well-known security identifiers and GUIDs used for ACL configuration.
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/443fe66f-c9b7-4c50-8c24-c708692bbf1d
$EnrollGUID = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"

$DomainUsersIdentity = [System.Security.Principal.SecurityIdentifier]::new(
    [System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid,
    (Get-ADDomain).DomainSID.value
)