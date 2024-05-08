using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ad_scanner.Domain
{
    public class CertificateAuthorityWebServices
    {
        public CertificateAuthorityWebServices()
        {
            LegacyAspEnrollmentUrls = new List<string>();
            EnrollmentWebServiceUrls = new List<string>();
            EnrollmentPolicyWebServiceUrls = new List<string>();
            NetworkDeviceEnrollmentServiceUrls = new List<string>();
        }
        public List<string> LegacyAspEnrollmentUrls { get; set; }
        public List<string> EnrollmentWebServiceUrls { get; set; }
        public List<string> EnrollmentPolicyWebServiceUrls { get; set; }
        public List<string> NetworkDeviceEnrollmentServiceUrls { get; set; }

    }
}
