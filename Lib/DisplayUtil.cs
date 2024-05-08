using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
    }

}
