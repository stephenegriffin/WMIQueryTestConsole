using System;
using System.Management;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace WMIQueryTestConsole
{
    /// <summary>
    /// Wrapper to WscGetSecurityProviderHealth of Wscapi.h
    /// </summary>
    public class WscApi
    {
        [DllImport("Wscapi.dll")]
        public static extern int WscGetSecurityProviderHealth(uint Providers, out _WSC_SECURITY_PROVIDER_HEALTH health);

        public enum _WSC_SECURITY_PROVIDER_HEALTH
        {
            WSC_SECURITY_PROVIDER_HEALTH_GOOD, // Green pillar in English locales
            WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED, // Yellow pillar in English locales
            WSC_SECURITY_PROVIDER_HEALTH_POOR,  // Red pillar in English locales
            WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, // Yellow pillar in English locales
        }

        public enum _WSC_SECURITY_PROVIDER
        {
            // Represents the aggregation of all firewalls for this computer.
            WSC_SECURITY_PROVIDER_FIREWALL = 0x1,
            // Represents the Automatic updating settings for this computer.
            WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 0x2,
            // Represents the aggregation of all antivirus products for this comptuer.
            WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x4,
            // Represents the aggregation of all antispyware products for this comptuer.
            WSC_SECURITY_PROVIDER_ANTISPYWARE = 0x8,
            // Represents the settings that restrict the access of web sites in each of the internet zones.
            WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 0x10,
            // Represents the User Account Control settings on this machine.
            WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 0x20,
            // Represents the running state of the Security Center service on this machine.
            WSC_SECURITY_PROVIDER_SERVICE = 0x40,

            WSC_SECURITY_PROVIDER_NONE = 0,

            // Aggregates all of the items that Security Center monitors.
            WSC_SECURITY_PROVIDER_ALL = WSC_SECURITY_PROVIDER_FIREWALL |
                                        WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS |
                                        WSC_SECURITY_PROVIDER_ANTIVIRUS |
                                        WSC_SECURITY_PROVIDER_ANTISPYWARE |
                                        WSC_SECURITY_PROVIDER_INTERNET_SETTINGS |
                                        WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL |
                                        WSC_SECURITY_PROVIDER_SERVICE
        }
    }


    /// <summary>
    /// This is the console program
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // Part 1 - Query Security Provider Health
            WscApi._WSC_SECURITY_PROVIDER_HEALTH health;
            Console.WriteLine("Following is a series of test to check on the health of key computer security parameters:");

            int hr = 0;
            hr = WscApi.WscGetSecurityProviderHealth((uint)WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTIVIRUS, out health);
            if (hr == 0)
                Console.WriteLine("{0} is {1}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTIVIRUS.ToString(), health.ToString());
            else
                Console.WriteLine("Can't get health state of {0}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTIVIRUS.ToString());

            hr = WscApi.WscGetSecurityProviderHealth((uint)WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_FIREWALL, out health);
            if (hr == 0)
                Console.WriteLine("{0} is {1}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_FIREWALL.ToString(), health.ToString());
            else
                Console.WriteLine("Can't get health state of {0}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_FIREWALL.ToString());

            hr = WscApi.WscGetSecurityProviderHealth((uint)WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS, out health);
            if (hr == 0)
                Console.WriteLine("{0} is {1}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS.ToString(), health.ToString());
            else
                Console.WriteLine("Can't get health state of {0}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS.ToString());

            hr = WscApi.WscGetSecurityProviderHealth((uint)WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTISPYWARE, out health);
            if (hr == 0)
                Console.WriteLine("{0} is {1}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTISPYWARE.ToString(), health.ToString());
            else
                Console.WriteLine("Can't get health state of {0}", WscApi._WSC_SECURITY_PROVIDER.WSC_SECURITY_PROVIDER_ANTISPYWARE.ToString());


            // Part 2 - Get the AV information
            var path = string.Format(@"\\{0}\root\SecurityCenter2", Environment.MachineName);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(path, "SELECT * FROM AntivirusProduct");
            string Result = "";
            foreach (ManagementObject queryObj in searcher.Get())
            {
                Result += "AV Product Information:" + Environment.NewLine;
                foreach (PropertyData propertyData in queryObj.Properties)
                {
                    Result += propertyData.Name.ToString() + ":" + propertyData.Value.ToString() + Environment.NewLine;
                }
            }
            Console.WriteLine();
            Console.WriteLine(Result.ToString());

            return;
        }

    }
}
