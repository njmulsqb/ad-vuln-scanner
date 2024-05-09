using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ad_scanner.Lib
{
     class DisplayUtil
    {

        public static string? GetDomainFromDN(string dn)
        {
            var index = dn.IndexOf("DC=");
            if (index == -1)
            {
                return null;
            }

            try
            {
                return dn.Substring(index + 3, dn.Length - index - 3).Replace(",DC=", ".");
            }
            catch
            {
                return null;
            }
        }

        public static string GetUserSidString(string sid, int padding = 30)
        {
            var user = "<UNKNOWN>";

            try
            {
                var sidObj = new SecurityIdentifier(sid);
                user = sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return $"{user}".PadRight(padding) + $"{sid}";
        }

        public static bool IsLowPrivSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(513|515|545)$") // Domain Users, Domain Computers, Users
                || sid == "S-1-1-0"   // Everyone
                || sid == "S-1-5-11"; // Authenticated Users
        }

    }

}
