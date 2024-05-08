using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Xml.Linq;
using Microsoft.Win32;

namespace ad_scanner.Domain
{
    class EnterpriseCertificateAuthority : CertificateAuthority
    {
        public List<string>? Templates { get; }
        public string? DnsHostname { get; }
        public string? FullName => $"{DnsHostname}\\{Name}";

        public EnterpriseCertificateAuthority(string distinguishedName, string? name, string? domainName, Guid? guid, string? dnsHostname, PkiCertificateAuthorityFlags? flags, List<X509Certificate2>? certificates, ActiveDirectorySecurity? securityDescriptor, List<string>? templates)
            : base(distinguishedName, name, domainName, guid, flags, certificates, securityDescriptor)
        {
            DnsHostname = dnsHostname;
            Templates = templates;
        }

        public ActiveDirectorySecurity? GetServerSecurityFromRegistry()
        {
            if (DnsHostname == null) throw new NullReferenceException("DnsHostname is null");
            if (Name == null) throw new NullReferenceException("Name is null");

            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Could not connect to the HKLM hive - {e.Message}");
                return null;
            }

            byte[] security;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                security = (byte[])key.GetValue("Security");
            }
            catch (SecurityException e)
            {
                Console.WriteLine($"[X] Could not access the 'Security' registry value: {e.Message}");
                return null;
            }

            var securityDescriptor = new ActiveDirectorySecurity();
            securityDescriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            return securityDescriptor;
        }

        public RawSecurityDescriptor? GetEnrollmentAgentSecurity()
        {
            //  NOTE: this appears to work even if admin rights aren't available on the remote CA server...
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            byte[] security;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                security = (byte[])key.GetValue("EnrollmentAgentRights");
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the 'EnrollmentAgentRights' registry value: {e.Message}");
            }

            return security == null ? null : new RawSecurityDescriptor(security, 0);
        }


        public bool IsUserSpecifiesSanEnabled()
        {
            if (DnsHostname == null) throw new NullReferenceException("DnsHostname is null");
            if (Name == null) throw new NullReferenceException("Name is null");

            // ref- https://blog.keyfactor.com/hidden-dangers-certificate-subject-alternative-names-sans
            //  NOTE: this appears to usually work, even if admin rights aren't available on the remote CA server
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            int editFlags;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                editFlags = (int)key.GetValue("EditFlags");
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the EditFlags registry value: {e.Message}");
            }

            // 0x00040000 -> EDITF_ATTRIBUTESUBJECTALTNAME2
            return (editFlags & 0x00040000) == 0x00040000;
        }

        //public CertificateAuthorityWebServices GetWebServices()
        //{
        //    if (DnsHostname == null) throw new NullReferenceException("DnsHostname is null");

        //    var webservices = new CertificateAuthorityWebServices();

        //    var protocols = new List<string>() { "http://", "https://" };

        //    protocols.ForEach(p =>
        //    {
        //        var LegacyAspEnrollmentUrl = $"{p}{DnsHostname}/certsrv/";
        //        var enrollmentWebServiceUrl = $"{p}{DnsHostname}/{Name}_CES_Kerberos/service.svc";
        //        var enrollmentPolicyWebServiceUrl = $"{p}{DnsHostname}/ADPolicyProvider_CEP_Kerberos/service.svc";
        //        var ndesEnrollmentUrl = $"{p}{DnsHostname}/certsrv/mscep/";

        //        if (HttpUtil.UrlExists(LegacyAspEnrollmentUrl, "NTLM"))
        //            webservices.LegacyAspEnrollmentUrls.Add(LegacyAspEnrollmentUrl);

        //        if (HttpUtil.UrlExists(enrollmentWebServiceUrl))
        //            webservices.EnrollmentWebServiceUrls.Add(enrollmentWebServiceUrl);

        //        if (HttpUtil.UrlExists(enrollmentPolicyWebServiceUrl))
        //            webservices.EnrollmentPolicyWebServiceUrls.Add(enrollmentPolicyWebServiceUrl);

        //        if (HttpUtil.UrlExists(ndesEnrollmentUrl))
        //            webservices.NetworkDeviceEnrollmentServiceUrls.Add(ndesEnrollmentUrl);
        //    });

        //    return webservices;
        //}
    }
}
