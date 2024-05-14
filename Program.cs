using ad_scanner.Domain;
using ad_scanner.Lib;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using static ad_scanner.Domain.CertificateTemplate;
using static ad_scanner.Lib.DisplayUtil;


string _certificateAuthority = null;
string _domain = "MARVEL.local";
string _ldapServer = null;

bool isDomainJoined = IsComputerJoinedToDomain();

//if (args.Length > 0)
//{
//    Console.WriteLine(args[0]);
//}

if (isDomainJoined)
{
    Console.WriteLine("The computer is joined to a domain.");
    FindTemplates();
}
else
{
    Console.WriteLine("The computer is not joined to a domain.");
}



 void FindTemplates()
{
    var ldap = new LdapOperations(new LdapSearchOptions() { Domain = _domain, LdapServer = _ldapServer });

    // get all of our current SIDs
    var ident = WindowsIdentity.GetCurrent();
    var currentUserSids = ident.Groups.Select(o => o.ToString()).ToList();
    currentUserSids.Add($"{ident.User}"); // make sure we get our current SID

    // enumerate information about every CA object
    var cas = ldap.GetEnterpriseCAs(_certificateAuthority);


    // enumerate information about all available templates
    var templates = ldap.GetCertificateTemplates();

    if (!templates.Any())
    {
        Console.WriteLine("\n[!] No available templates found!\n");
        return;
    }

    ShowVulnerableTemplates(templates, cas);
    //ShowVulnerableTemplates(templates, cas, currentUserSids);

}

 void ShowVulnerableTemplates(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas, List<string>? currentUserSids = null)
{
    foreach (var t in templates.Where(t => t.Name == null))
    {
        Console.WriteLine($"[!] Warning: Could not get the name of the template {t.DistinguishedName}. Analysis will be incomplete as a result.");
    }

    var unusedTemplates = (
        from t in templates
        where t.Name != null && !cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
        select $"{t.Name}").ToArray();

    var vulnerableTemplates = (
        from t in templates
        where t.Name != null && cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
        select $"{t.Name}").ToArray();

    if (unusedTemplates.Any())
    {
        Console.WriteLine("\n[!] Vulnerable certificate templates that exist but an Enterprise CA does not publish:\n");
        Console.WriteLine($"    {string.Join("\n    ", unusedTemplates)}\n");
    }

    //Console.WriteLine(!vulnerableTemplates.Any()
    //    ? "\n[+] No Vulnerable Certificates Templates found!\n"
    //    : "\n[!] Vulnerable Certificates Templates :\n");

    foreach (var template in templates)
    {
        if (!IsCertificateTemplateVulnerable(template, currentUserSids))
            continue;

        foreach (var ca in cas)
        {
            if (ca.Templates == null)
            {
                Console.WriteLine($"   Warning: Unable to get the published templates on the CA {ca.DistinguishedName}. Ignoring it...");
                continue;
            }
            if (template.Name == null)
            {
                Console.WriteLine($"   Warning: Unable to get the name of the template {template.DistinguishedName}. Ignoring it...");
                continue;
            }

            if (!ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                continue;

            PrintCertTemplate(ca, template);
        }
    }
}
 void PrintCertTemplate(EnterpriseCertificateAuthority ca, CertificateTemplate template)
{
    //Console.WriteLine($"    CA Name                               : {ca.FullName}");
    //Console.WriteLine($"    Template Name                         : {template.Name}");
    //Console.WriteLine($"    Schema Version                        : {template.SchemaVersion}");
    //Console.WriteLine($"    Validity Period                       : {template.ValidityPeriod}");
    //Console.WriteLine($"    Renewal Period                        : {template.RenewalPeriod}");
    //Console.WriteLine($"    msPKI-Certificate-Name-Flag          : {template.CertificateNameFlag}");
    //Console.WriteLine($"    mspki-enrollment-flag                 : {template.EnrollmentFlag}");
    //Console.WriteLine($"    Authorized Signatures Required        : {template.AuthorizedSignatures}");


    // ESC 1 Checks
    var certificateApplicationPolicyFriendlyNames = template.ApplicationPolicies == null
      ? new[] { "<null>" }
      : template.ApplicationPolicies.Select(o => ((new Oid(o)).FriendlyName))
      .OrderBy(s => s)
      .ToArray();

    var sd = template.SecurityDescriptor;

    var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));
 

    var enrollmentPrincipals = new List<string>();

    var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
    foreach (ActiveDirectoryAccessRule rule in rules)
    {
        if ($"{rule.AccessControlType}" != "Allow")
            continue;

        var sid = rule.IdentityReference.ToString();
   

        if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
        {
     
            switch ($"{rule.ObjectType}")
            {
                case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                    enrollmentPrincipals.Add(GetUserSidString(sid));
                    break;
            }
        }
    }

    if (template.CertificateNameFlag.ToString() == "ENROLLEE_SUPPLIES_SUBJECT" && template.EnrollmentFlag.ToString() == "NONE" && template.AuthorizedSignatures.ToString() == "0" && certificateApplicationPolicyFriendlyNames.Contains("Client Authentication"))
    {
        foreach (string principal in enrollmentPrincipals)
        {
            if (principal.Equals("NT AUTHORITY\\Authenticated UsersS-1-5-11", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("ESC1 Vulnerability Exists");
            }
        }
        
    }


}

    bool IsCertificateTemplateVulnerable(CertificateTemplate template, List<string>? currentUserSids = null)
    {
        if (template.SecurityDescriptor == null)
            throw new NullReferenceException($"Could not get the security descriptor for the template '{template.DistinguishedName}'");

        var ownerSID = $"{template.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).Value}";

        if (currentUserSids == null)
        {
            // Check 1) is the owner a low-privileged user?
            if (IsLowPrivSid(ownerSID))
            {
                return true;
            }
        }
        else
        {
            // Check 1) is the owner is a principal we're nested into
            if (currentUserSids.Contains(ownerSID))
            {
                return true;
            }
        }

        // Check misc) Can low privileged users/the current user enroll?
        var lowPrivilegedUsersCanEnroll = false;

        // Check 2) do low-privileged users/the current user have edit rights over the template?
        var vulnerableACL = false;
        foreach (ActiveDirectoryAccessRule rule in template.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (currentUserSids == null)
            {
                // check for low-privileged control relationships
                if (
                    ($"{rule.AccessControlType}" == "Allow")
                    && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                    && (
                        ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                    )
                )
                {
                    vulnerableACL = true;
                }
                // check for low-privileged enrollment
                else if (
                    ($"{rule.AccessControlType}" == "Allow")
                    && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                    && (
                        ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                        && (
                            $"{rule.ObjectType}" == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                            || $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000"
                        )
                    )
                )
                {
                    lowPrivilegedUsersCanEnroll = true;
                }
            }
            else
            {
                // check for current-user control relationships
                if (
                    ($"{rule.AccessControlType}" == "Allow")
                    && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                    && (
                        ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                        || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                    )
                )
                {
                    vulnerableACL = true;
                }

                // check for current-user enrollment
                if (
                    ($"{rule.AccessControlType}" == "Allow")
                    && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                    && (
                        ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                        && (
                            $"{rule.ObjectType}" == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                            || $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000"
                        )
                    )
                )
                {
                    lowPrivilegedUsersCanEnroll = true;
                }
            }

        }

        if (vulnerableACL)
        {
            return true;
        }


        // Check 3) Is manager approval enabled?
        var requiresManagerApproval = template.EnrollmentFlag != null && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
        if (requiresManagerApproval) return false;

        // Check 4) Are there now authorized signatures required?
        if (template.AuthorizedSignatures > 0) return false;


        // Check 5) If a low priv'ed user can request a cert with EKUs used for authentication and ENROLLEE_SUPPLIES_SUBJECT is enabled, then privilege escalation is possible
        var enrolleeSuppliesSubject = template.CertificateNameFlag != null && ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
        var hasAuthenticationEku =
            template.ExtendedKeyUsage != null &&
            (template.ExtendedKeyUsage.Contains(CommonOids.SmartcardLogon) ||
            template.ExtendedKeyUsage.Contains(CommonOids.ClientAuthentication) ||
            template.ExtendedKeyUsage.Contains(CommonOids.PKINITClientAuthentication));

        if (lowPrivilegedUsersCanEnroll && enrolleeSuppliesSubject && hasAuthenticationEku) return true;


        // Check 6) If a low priv'ed user can request a cert with any of these EKUs (or no EKU), then privilege escalation is possible
        var hasDangerousEku =
            template.ExtendedKeyUsage == null
            || !template.ExtendedKeyUsage.Any() // No EKUs == Any Purpose
            || template.ExtendedKeyUsage.Contains(CommonOids.AnyPurpose)
            || template.ExtendedKeyUsage.Contains(CommonOids.CertificateRequestAgent)
            || (template.ApplicationPolicies != null && template.ApplicationPolicies.Contains(CommonOids.CertificateRequestAgentPolicy));

        if (lowPrivilegedUsersCanEnroll && hasDangerousEku) return true;


        // Check 7) Does a certificate contain the  DISABLE_EMBED_SID_OID flag + DNS and DNS SAN flags
        if (template.CertificateNameFlag == null || template.EnrollmentFlag == null)
        {
            return false;
        }

        if ((((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS)
            || ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_REQUIRE_DNS_AS_CN))
            && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.NO_SECURITY_EXTENSION))
        {
            return true;
        }

        return false;
    }
    static bool IsComputerJoinedToDomain()
    {
        try
        {
            Domain.GetComputerDomain(); // This method will throw an exception if not joined to a domain
            return true;
        }
        catch (ActiveDirectoryObjectNotFoundException)
        {
            return false;
        }
    }
