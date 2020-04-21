#undef MAPDRIVES
using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Security.AccessControl;

namespace ScanEntitlements
{
    class Program
    {
        static OIMNTFSTableAdapters.FilesystemsTableAdapter fileSystemsTable = new OIMNTFSTableAdapters.FilesystemsTableAdapter();
        static OIMNTFS.FilesystemsDataTable fileSystems = new OIMNTFS.FilesystemsDataTable();
        static OIMNTFSTableAdapters.TopLevelNodesTableAdapter topLevelNodesTable = new OIMNTFSTableAdapters.TopLevelNodesTableAdapter();
        static OIMNTFS.TopLevelNodesDataTable topLevelNodes = new OIMNTFS.TopLevelNodesDataTable();
        static OIMNTFSTableAdapters.ExcludeNodesTableAdapter excludeNodesTable = new OIMNTFSTableAdapters.ExcludeNodesTableAdapter();
        static OIMNTFS.ExcludeNodesDataTable excludeNodes = new OIMNTFS.ExcludeNodesDataTable();
        static OIMNTFSTableAdapters.NodesTableAdapter nodesTable = new OIMNTFSTableAdapters.NodesTableAdapter();
        static OIMNTFSTableAdapters.EntitlementsTableAdapter entitlementsTable = new OIMNTFSTableAdapters.EntitlementsTableAdapter();
        static Boolean createCopy = false;
        static Boolean writeDatabase = false;

        static long entitlementcounter = 0;
        static long foldercounter = 0;
        static long protectedcounter = 0;

        static SqlConnection conn = new SqlConnection("Data Source=10.112.139.4;Initial Catalog=oimntfs;User Id = oimntfsdbo; Password = HbLjSEsgv/9ctvj2pYosOJT7UPVpid3qdJP5RPBVbG8=");
        static SqlCommand getNewNodeID = new SqlCommand("SELECT CAST(ISNULL(IDENT_CURRENT('Nodes'), 0) as bigint)", conn);
        static ADCache ad = null;
        static DirectoryInfo target = null;
        static string targetprefix = null;
        static FileSystemAccessRule nbe2702full = new FileSystemAccessRule("nbe2702", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);

        static void UpdateTopLevelNodes(OIMNTFS.FilesystemsRow fileSystem)
        {
            DirectoryInfo dInfo = null;
            DirectorySecurity dSecurity = null;

            string[] topLevelNodePaths = (string[])null;
            Int64 filesystemID = fileSystem.ID;

            try
            {
                topLevelNodePaths = Directory.GetDirectories(fileSystem.DriveRoot, "*", SearchOption.TopDirectoryOnly);
            }
            catch (Exception e)
            {
                Console.WriteLine("Directories in {0} cannot be read.", fileSystem.DriveRoot);
                Console.WriteLine("{0}", e.Message);
                return;
            }
            foreach (string topLevelNodePath in topLevelNodePaths)
            {
                if (excludeNodes.Select("'" + topLevelNodePath + "' LIKE excludeNode").Length > 0)
                    continue;
                try
                {
                    dInfo = new DirectoryInfo(topLevelNodePath);
                    dSecurity = dInfo.GetAccessControl();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Directory info in {0} cannot be read.", topLevelNodePath);
                    Console.WriteLine("{0}", e.Message);
                    continue;
                }
                DateTime lastWrite = dInfo.LastWriteTimeUtc;
                DateTime lastAccess = dInfo.LastAccessTimeUtc;
                string ownerSID = null;
                string owner = null;
                try
                {
                    ownerSID = dSecurity.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)).Value;
                    owner = ad.getObjectName(ownerSID);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unable to read owner of {0}", topLevelNodePath);
                    Console.WriteLine(e.Message);
                }
                Boolean isProtected = dSecurity.AreAccessRulesProtected;

                if (topLevelNodes.Select("FullPath = '" + dInfo.FullName + "'").Length == 0)
                {
                    Console.WriteLine("Found new node '{0}'", dInfo.FullName);
                    OIMNTFS.TopLevelNodesRow newTopLevelNode = topLevelNodes.NewTopLevelNodesRow();

                    newTopLevelNode.FilesystemID = filesystemID;
                    newTopLevelNode.ScanDepth = fileSystem.Depth;
                    newTopLevelNode.FullPath = dInfo.FullName;
                    newTopLevelNode.Name = dInfo.Name;
                    newTopLevelNode.LastAccessUTC = dInfo.LastAccessTimeUtc;
                    newTopLevelNode.LastWriteUTC = dInfo.LastWriteTimeUtc;
                    newTopLevelNode.LastScanned = DateTime.MinValue;
                    newTopLevelNode.FirstSeen = DateTime.UtcNow;
                    newTopLevelNode.DataOwner = owner;
                    newTopLevelNode.isProtected = isProtected;

                    topLevelNodes.AddTopLevelNodesRow(newTopLevelNode);
                }
            }
            if (writeDatabase)
                topLevelNodesTable.Update(topLevelNodes);
        }

        public static void ProcessDirectory(string scanPath, int level, int maxlevel, Int64 TopLevelNodeID, Int64 ParentNodeID)
        {
            DateTime start = DateTime.Now;

            DirectoryInfo dInfo = null;
            DirectorySecurity dSecurity = null;
            string fullPath = null;
            string name = null;
            string owner = "<unknown>";
            DateTime lastAccess;
            DateTime lastWrite;
            Boolean isProtected = false;
            Int64 nodeID = 0;

            DirectoryInfo tInfo = null;
            DirectorySecurity tSecurity = null;
            string targetPath = "";

            // check if folder name is too long
            if (scanPath.Length > 248)
            {
                Console.WriteLine("\rPath too long: {0} ({1} characters)", scanPath, scanPath.Length);
                return;
            }
            // Check if foldername is in exclusion list
            try
            {
                if (excludeNodes.Select("'" + scanPath.Replace("'", "''") + "' LIKE excludeNode").Length > 0)
                    return;
            }
            catch (Exception e)
            {
                Console.WriteLine("\rFailed to check exclude list for {0}: {1}.", scanPath, e.Message);
                // do not return
            }


            foldercounter++;
            // now read directory information
            try
            {
                dInfo = new DirectoryInfo(scanPath);
                lastAccess = dInfo.LastAccessTimeUtc;
                lastWrite = dInfo.LastWriteTimeUtc;
                fullPath = dInfo.FullName;
                name = dInfo.Name;
            }
            catch (Exception e)
            {
                Console.WriteLine("\rFailed to read directory info for {0}\n{1}", scanPath, e.Message);
                return;
            }
            // read directory security information
            try
            {
                dSecurity = dInfo.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                name = dInfo.Name;
            }
            catch (Exception e)
            {
                Console.WriteLine("\rFailed to read security info for {0}\n{1}", scanPath, e.Message);
                return;
            }

            // now identify owner
            try
            {
                string SID = dSecurity.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)).Value;
                owner = ad.getObjectName(SID);
                isProtected = dSecurity.AreAccessRulesProtected;
            }
            catch (Exception e)
            {
                Console.WriteLine("\rFailed to read ownership info for {0}\n{1}", scanPath, e.Message);
            }

            if (isProtected)
                protectedcounter++;

            // insert node found into nodes table (previously emptied for related toplevelfolder)
            if (writeDatabase)
            {
                try
                {
                    nodesTable.Insert(fullPath, name, level, TopLevelNodeID, ParentNodeID, owner, isProtected, lastAccess, lastWrite, DateTime.UtcNow);
                    nodeID = (Int64)getNewNodeID.ExecuteScalar();
                }
                catch (Exception e)
                {
                    Console.WriteLine("INSERTing new nodes row into DB failed.");
                    Console.WriteLine(e.Message);
                }
            }
            // create copy as target folder
            if (createCopy)
            {
                try
                {
                    targetPath = targetprefix + fullPath.Replace(":", "_").Replace("\\\\", "__");
                    tInfo = Directory.CreateDirectory(targetPath);
                    tSecurity = new DirectorySecurity();
                }
                catch (Exception e)
                {
                    Console.WriteLine("\nFailed to create {0}\n{1}", targetPath, e.Message);
                    targetPath = "";
                }
            }

            // analyse all access rules (explicit access rules only, no inherited access rules)
            foreach (FileSystemAccessRule fsar in dSecurity.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)))
            {
                entitlementcounter++;

                string SID = fsar.IdentityReference.Value;
                string objectName = ad.getObjectName(SID);
                string objectClass = ad.getObjectClass(SID);
                string accessRights = fsar.FileSystemRights.ToString();
                string accessType = fsar.AccessControlType.ToString();
                string rulePropagation = fsar.PropagationFlags.ToString();
                string ruleInheritance = fsar.InheritanceFlags.ToString();

                if (writeDatabase)
                {
                    try
                    {
                        entitlementsTable.Insert(nodeID, objectName, objectClass, accessRights, accessType, rulePropagation, ruleInheritance, DateTime.UtcNow);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("\rFailed to insert entitlements for {0}\n{1}", objectName, e.Message);
                        return;
                    }
                }

                if (createCopy) // copy access information to target
                {
                    Console.Write("\rLevel {0}, Folders {1}, Entitlements {2}, Protected {3}, set security info...             ", level, foldercounter, entitlementcounter, protectedcounter);
                    if (objectName != SID) // leave out SIDs
                    {
                        try
                        {
                            tSecurity.AddAccessRule(new FileSystemAccessRule(objectName, fsar.FileSystemRights, fsar.InheritanceFlags, fsar.PropagationFlags, fsar.AccessControlType));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("\rfailed to set security info for {0}: {1}={2}                                             ", objectName, fsar.FileSystemRights.ToString(), fsar.AccessControlType.ToString());
                            Console.WriteLine("{0}", e.Message);
                        }
                    }
                }
                Console.Write("\rLevel {0}, Folders {1}, Entitlements {2}, Protected {3}, Runtime {4}               ", level, foldercounter, entitlementcounter, protectedcounter, (DateTime.Now - start).ToString());
            } // end foreach fsar

            if (createCopy)
            {
                if (dSecurity.AreAccessRulesProtected)
                {
                    try
                    {
                        tSecurity.AddAccessRule(nbe2702full);
                        tSecurity.SetAccessRuleProtection(true, false);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("\rfailed to set inheritance protection for {0}                   ", targetPath);
                        Console.WriteLine("{0}", e.Message);
                    }
                }
                Console.Write("\rLevel {0}, Folders {1}, Entitlements {2}, Protected {3}, write security info...              ", level, foldercounter, entitlementcounter, protectedcounter);
                try
                {
                    tInfo.SetAccessControl(tSecurity);
                }
                catch (Exception e)
                {
                    Console.WriteLine("\rfailed to write security info to {0}                         ", targetPath);
                    Console.WriteLine("{0}", e.Message);
                }
            }

            if (level < maxlevel)
            {
                Console.Write("\rLevel {0}, Folders {1}, Entitlements {2}, Protected {3}, next level ...                    ", level, foldercounter, entitlementcounter, protectedcounter);
                string[] subDirectories = null;
                try
                {
                    subDirectories = Directory.GetDirectories(dInfo.FullName);
                }
                catch (Exception e)
                {
                    Console.WriteLine("\runable to read subdirectories of {0}                         ", dInfo.FullName);
                    Console.WriteLine("{0}", e.Message);
                    return;
                }
                Console.Write("\rLevel {0}, Folders {1}, Entitlements {2}, Protected {3}, Runtime {4}                      ", level, foldercounter, entitlementcounter, protectedcounter, (DateTime.Now - start).ToString());
                foreach (string subdirectory in subDirectories)
                    ProcessDirectory(subdirectory, level + 1, maxlevel, TopLevelNodeID, nodeID);
            }
        }

        static void Main(string[] args)
        {
            DateTime start = DateTime.Now;

            if (args.Length > 0)
            {
                if (!args[0].StartsWith("\\\\"))
                {
                    Console.WriteLine("Please provide target folder in UNC format (\\\\server\\share\\path..).");
                    return;
                }
                else
                {
                    target = new DirectoryInfo(args[0]);
                }
            }

#if MAPDRIVES
            // Preparation: unmap all network drives
            string[] drives = Directory.GetLogicalDrives();
            NetworkDrive networkDrive = new NetworkDrive();
            networkDrive.Persistent = true;
            networkDrive.SaveCredentials = true;
            networkDrive.Force = true;

            foreach (string drive in drives)
            {
                try
                {
                    networkDrive.LocalDrive = drive;
                    networkDrive.UnMapDrive();
                    Console.WriteLine("Drive {0} mapping removed (net use {0} /d)", drive);
                }
                catch (Exception e)
                {
                    if (e.HResult != -2147467259)
                    {
                        Console.WriteLine("unable to unmap {0}", drive);
                        Console.WriteLine("{0}", e.ToString());
                    }
                }
            }
#endif

#if MAPDRIVES
            try
            {
                networkDrive.LocalDrive = "Z:";
                networkDrive.ShareName = args[0];
                try { networkDrive.UnMapDrive(); }
                catch { }
                try { networkDrive.MapDrive(); }
                catch (Exception e)
                {
                    if (e.HResult == -2147467259)
                    {
                        string username = "";
                        string password = "";

                        ConsoleColor foregroundColor = Console.ForegroundColor;
                        ConsoleColor backgroundColor = Console.BackgroundColor;
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Current user context is not allowed to mount {0}", args[0]);
                        Console.ForegroundColor = foregroundColor;
                        Console.Write("Enter username: ");
                        username = Console.ReadLine();
                        Console.Write("Enter password: ");
                        Console.BackgroundColor = foregroundColor;
                        password = Console.ReadLine();
                        Console.BackgroundColor = backgroundColor;

                        networkDrive.MapDrive(username, password);
                    }
                }
                target = new DirectoryInfo(networkDrive.LocalDrive);
                Console.WriteLine("Target {0} mapped to drive {1}.", args[0], target.FullName);
            }
            catch (Exception e)
            {
                Console.WriteLine("unable to map drive {0} to {1}", networkDrive.LocalDrive, networkDrive.ShareName);
                Console.WriteLine("{0}", e.ToString());
            }
#endif
            targetprefix = target.FullName;
            if (!targetprefix.EndsWith("\\"))
                targetprefix += "\\";

            createCopy = true;
            Console.WriteLine("Target for folder copy is {0}...", targetprefix);

            // Preparation: open database and read information
            conn.Open();

            Console.WriteLine("Reading data tables from database {0}...", conn.Database);

            fileSystemsTable.Connection = conn;
            fileSystemsTable.Fill(fileSystems);

            excludeNodesTable.Connection = conn;
            excludeNodesTable.Fill(excludeNodes);

            topLevelNodesTable.Connection = conn;
            topLevelNodesTable.Fill(topLevelNodes);

            nodesTable.Connection = conn;
            entitlementsTable.Connection = conn;
            
            SqlCommand delnodes = conn.CreateCommand();
            delnodes.CommandText = "DELETE FROM [OIMNTFS].[dbo].[Nodes] WHERE TopLevelNodeID = @ID";
            delnodes.Parameters.Add("@ID", SqlDbType.BigInt);

            // final preparation step: load AD objects (users, groups)
            ad = new ADCache("LDAP://10.112.128.3/DC=nrwbanki,DC=de");
            
            // now read top level folders
            try
            {
                Console.WriteLine("Reading file systems...");
                foreach (OIMNTFS.FilesystemsRow fileSystem in fileSystems.Rows)
                {
#if MAPDRIVES
                    networkDrive.LocalDrive = fileSystem.DriveRoot.Substring(0, 2);
                    networkDrive.Persistent = false;
                    networkDrive.SaveCredentials = false;
                    networkDrive.Force = true;
                    networkDrive.ShareName = "\\\\" + fileSystem.ProviderIP + "\\" + fileSystem.Share;
                    Console.WriteLine("Mapping drive {0} to {1}", networkDrive.LocalDrive, networkDrive.ShareName);
                    try
                    {
                        switch (fileSystem.Type)
                        {
                            case 0:
                                networkDrive.MapDrive();
                                break;
                            case 1:
                                networkDrive.MapDrive(fileSystem.User, fileSystem.Password);
                                break;
                            default:
                                networkDrive.MapDrive(fileSystem.User, fileSystem.Password);
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("unable to map drive {0} to {1}", networkDrive.LocalDrive, networkDrive.ShareName);
                        Console.WriteLine("{0}", e.ToString());
                    }

#endif
                    Console.WriteLine("Updating top level folders of {0}...", fileSystem.DriveRoot);
                    UpdateTopLevelNodes(fileSystem);
                }

                // now start to process all top level nodes
                foreach (OIMNTFS.TopLevelNodesRow topLevelNode in topLevelNodes.OrderBy(n => n.LastScanned))
                {
                    start = DateTime.Now;
                    foldercounter = 0;
                    entitlementcounter = 0;
                    protectedcounter = 0;

                    /*
                    SqlTransaction tran = conn.BeginTransaction();
                    getNewNodeID.Transaction = tran;
                    nodesTable.Transaction = tran;
                        
                    delnodes.Transaction = tran;
                    */
                    if (writeDatabase)
                    {
                        Console.WriteLine("Deleting old scan information for {0}...", topLevelNode.FullPath);
                        delnodes.Parameters["@ID"].Value = topLevelNode.ID;
                        delnodes.ExecuteNonQuery();
                    }

                    Console.WriteLine("Scanning {0} down to level {1}...", topLevelNode.FullPath, topLevelNode.ScanDepth);
                    ProcessDirectory(topLevelNode.FullPath, 1, topLevelNode.ScanDepth, topLevelNode.ID, 0);
                    Console.Write("\nDone.");
                    if (writeDatabase)
                    {
                        Console.Write(" Updating database...");
                        try
                        {
                            (topLevelNodes.FindByID(topLevelNode.ID)).LastScanned = DateTime.Now;
                            topLevelNodesTable.Update(topLevelNodes);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("\rFailed to update last scanned timestamp for {0}", topLevelNode.FullPath);
                            Console.WriteLine(e.Message);
                        }
                    }
                    Console.Write("                                                                                                        \r");
                    Console.WriteLine("{0} completed on {1:hh:mm:ss}.\n{2} folders read ({3:0.0} folders per second)\n", topLevelNode.FullPath, DateTime.Now, foldercounter, foldercounter / (DateTime.Now - start).TotalSeconds, foldercounter);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\n\nException in outer main(). - {0}", e.Source);
                Console.WriteLine(e.Message);
                Console.WriteLine(e.StackTrace);
            }
            finally
            {
                if (writeDatabase)
                {
                    string cmdtext = @"
                    WITH NodesMax AS (
                        SELECT TopLevelNodes.ID, maxlastaccess = MAX(LastAccess), maxlastwrite = MAX(LastWrite)
                        FROM TopLevelNodes
                        JOIN Nodes ON Nodes.TopLevelNodeID = TopLevelNodes.ID
                        GROUP BY TopLevelNodes.ID
                    )
                    UPDATE TopLevelNodes
                    SET
                        LastTreeAccessUTC = NodesMax.maxlastaccess,
                        LastTreeWriteUTC = NodesMax.maxlastwrite
                        FROM ToplevelNodes
                        JOIN NodesMax ON NodesMax.ID = TopLevelNodes.ID";
                    (new SqlCommand(cmdtext, conn)).ExecuteNonQuery();
                    conn.Close();
                }
            }

            DateTime ende = DateTime.Now;
            double dauer = (ende - start).TotalMilliseconds;
            Console.WriteLine("\n\nVerarbeitung beendet ({0}).", DateTime.Now.ToLocalTime());
            Console.WriteLine("Dauer: {0}", (ende - start).ToString());
            Console.WriteLine("Durchsatz: {0} Verzeichnisse pro Sekunde", 1000.0 * foldercounter / dauer);
            Console.Write("\nPress enter to close.");
            Console.Read();
        }
    }
}
