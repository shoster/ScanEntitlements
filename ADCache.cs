using System;
using System.Collections.Generic;
using System.DirectoryServices;

namespace ScanEntitlements
{
    class ADCache
    {
        public struct Properties
        {
            public Properties(string sid, SearchResult entry)
            {
                samAccountName = entry.Properties["samAccountName"][0].ToString();
                canonicalName = entry.Properties["canonicalName"][0].ToString();
                SID = sid;
                distinguishedName = entry.Properties["distinguishedName"][0].ToString();
                path = entry.Path;

                objectClass = entry.Properties["objectClass"][entry.Properties["objectClass"].Count - 1].ToString();
                switch (samAccountName)
                {
                    case "Administrators":
                        objectClass = "system";
                        break;
                    case "SPT_Search_filer":
                        objectClass = "system";
                        break;
                    case "SPP_Search_Filer":
                        objectClass = "system";
                        break;
                    case "GF-RD021-DA":
                        objectClass = "system";
                        break;
                    default:
                        if (samAccountName.StartsWith("SPT_Search"))
                            objectClass = "system";
                        else if (samAccountName.StartsWith("SPP_Search"))
                            objectClass = "system";
                        else if (samAccountName.StartsWith("SPP_Search"))
                            objectClass = "system";
                        else if (samAccountName.StartsWith("Domain "))
                            objectClass = "system";
                        break;
                }
            }
            public string samAccountName { get; set; }
            public string objectClass { get; set; }
            public string canonicalName { get; set; }
            public string SID { get; set; }
            public string path { get; set; }
            public string distinguishedName { get; set; }
        }
        static Dictionary<string, Properties> cache = new Dictionary<string, Properties>(200000);
        public ADCache(string path)
        {
            try
            {
                DateTime start = DateTime.Now;
                string[] properties = new string[] { "samAccountName", "objectClass", "canonicalName", "objectSID", "distinguishedName" };
                string filter = "(|(objectClass=user)(objectClass=group))";

                Console.WriteLine("Connecting to {0}...", path);
                DirectoryEntry directoryEntry;

                try
                {
                    directoryEntry = new DirectoryEntry(path);
                    directoryEntry.RefreshCache(properties);
                }
                catch
                {
                    string username = "";
                    string password = "";

                    ConsoleColor foregroundColor = Console.ForegroundColor;
                    ConsoleColor backgroundColor = Console.BackgroundColor;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Current user context is not allowed to read from AD.");
                    Console.WriteLine("Please provide user credentials entitled to read from {0}.", path);
                    Console.ForegroundColor = foregroundColor;
                    Console.Write("Enter username: ");
                    username = Console.ReadLine();
                    Console.Write("Enter password: ");
                    Console.BackgroundColor = foregroundColor;
                    password = Console.ReadLine();
                    Console.BackgroundColor = backgroundColor;

                    directoryEntry = new DirectoryEntry(path, username, password);
                    directoryEntry.RefreshCache(properties);
                }

                Console.WriteLine("Reading all ad user and group objects...");
                DirectorySearcher ds = new System.DirectoryServices.DirectorySearcher(directoryEntry, filter, properties);
                ds.SearchScope = SearchScope.Subtree;
                ds.CacheResults = true;
                ds.ClientTimeout = TimeSpan.FromMinutes(120);
                ds.PageSize = 100;

                SearchResultCollection entries = ds.FindAll();
                foreach (SearchResult entry in entries)
                {
                    System.Security.Principal.SecurityIdentifier binSID = new System.Security.Principal.SecurityIdentifier((byte[])entry.Properties["objectSID"][0], 0);
                    string sid = binSID.ToString();
                    string samAccountName = entry.Properties["samAccountName"][0].ToString();
                    //Console.WriteLine("{0} - {1}", sid, samAccountName);
                    Console.Write("\r{0} objects read..", cache.Count);
                    if (!cache.ContainsKey(sid))
                        cache.Add(sid, new Properties(sid, entry));
                }
                Console.WriteLine("\r{0} objects found. Loading AD took actually {1}", cache.Count, (DateTime.Now - start).ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Reading AD failed: {0}", e.Message);
                throw new Exception("Reading AD failed.");
            }
        }

        public int Count()
        {
            return cache.Count;
        }

        public bool isADObject(string samAccountName)
        {
            return cache.ContainsKey(samAccountName);
        }

        public string getObjectClass(string SID)
        {
            Properties properties;

            if (cache.TryGetValue(SID, out properties))
                return properties.objectClass;
            else
                return "deleted";
        }
        public string getObjectName(string SID)
        {
            Properties properties;

            if (cache.TryGetValue(SID, out properties))
                return properties.samAccountName;
            else
                return SID;
        }

        public Properties getProperties(string objectName)
        {
            Properties properties;

            if (cache.TryGetValue(objectName, out properties))
                return properties;
            else
                return new Properties();
        }
    }
}
