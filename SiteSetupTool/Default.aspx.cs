using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

using System.IO;
using System.Linq;

using System.Net.Mail;
using System.Security;
using System.Security.AccessControl;
using System.Text.RegularExpressions;


using Microsoft.Web.Administration;
using System.Security.Principal;
using System.Runtime.InteropServices;
using MySql.Data.MySqlClient;
using System.Data;
using Microsoft.SqlServer.Management.Smo;
using Microsoft.SqlServer;
using System.Configuration;

namespace SiteSetupTool
{
    public partial class Default : System.Web.UI.Page
    {
        private String folderGroup;
        private String userName;
        private String DBname;
        private String FTPusername;
        private String FTPpassword;
        private String IISusername;
        private String IISpassword;
        private String dbUsername;
        private String dbPassword;
        private String folderPath;
        private String logPath;

        protected void Page_Load(object sender, EventArgs e) { }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(
           string lpszUsername,
           string lpszDomain,
           string lpszPassword,
           int dwLogonType,
           int dwLogonProvider,
           out IntPtr phToken);

        private const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;

        protected void BtnExecuteScript_Click(object sender, EventArgs e)
        {
            IntPtr userToken = IntPtr.Zero;

            bool success = LogonUser(
              loginUserName.Text.Split('\\')[1], loginUserName.Text.Split('\\')[0], loginPassword.Text,
             LOGON32_LOGON_NETWORK_CLEARTEXT,//2,
              0, //0
              out userToken);

            if (!success)
            {
                throw new SecurityException("Logon user failed");
            }

            using (WindowsIdentity.Impersonate(userToken))
            {
                BtnExecuteScript.Enabled = false;
                Folders(DomainName.Text); //TESTED - WORKING
                Logins(DomainName.Text); //TESTED - WORKING
                ActiveDirectorySetup(ChkBoxOverwrite.Checked); //Doesn't set 'user cannot change password' flags
                Permissions(); //TESTED - WORKING
                MakeAnIIS(DomainName.Text);
                MakeAnFTP(DomainName.Text);

                if (MySqlChkBox.Checked)
                {
                    MySQLSetup(DomainName.Text);
                }
                else if (SqlChkBox.Checked)
                {
                    SQlserverSetup(DomainName.Text); //tested working but login is hardcoded? 
                    backUpSQL();
                }
            }
        }

        public void Folders(String domainName)
        {
            var ad = new Regex("^[a-dA-D]");
            var eh = new Regex("^[e-hE-H]");
            var il = new Regex("^[i-lI-L]");
            var mp = new Regex("^[m-pM-P]");
            var qt = new Regex("^[q-tQ-T]");
            var uz = new Regex("^[u-zU-Z]");

            Regex[] foldersRegex = { ad, eh, il, mp, qt, uz };
            String[] folders = { "A-D", "E-H", "I-L", "M-P", "Q-T", "U-Z" };
            int count = 0;

            foreach (Regex pattern in foldersRegex)
            {
                if (pattern.IsMatch(domainName))
                {
                    folderGroup = folders[count];
                    WriteOut(folderGroup);
                    break;
                }
                count++;
            }

            folderPath += @"\\domain\wwwroot-" + folderGroup + @"\" + domainName;
            logPath += @"\\domain\log-" + folderGroup + @"\" + domainName + @"%computername%";

            String[] folderTypes = { folderPath, logPath };

            try
            {
                foreach (String folder in folderTypes)
                {
                    if (Directory.Exists(folder))
                    {
                        WriteOut("Folders already exist for this domain name");
                        return;
                    }
                    Directory.CreateDirectory(folder);
                    WriteOut("Folder created at " + folder);
                }

            }
            catch (Exception e)
            {
                WriteOut("Folder creation failed: " + e);
                RollbackFolder(folderTypes);
            }
        }

        private void WriteOut(string text)
        {
            TxtOutput.Text += string.Format("{0}\n", text);

        }

        private void RollbackFolder(IEnumerable<string> folderTypes)
        {
            foreach (var folder in folderTypes.Where(Directory.Exists))
            {
                WriteOut(string.Format("Deleting Directory{0}", folder));
                Directory.Delete(folder);
                return;
            }

        }

        protected void emailResults(object sender, EventArgs e)
        {
            try
            {
                DirectoryEntry entry =
                    new DirectoryEntry(
                       getConfigSections("ADServer"),//"LDAP://domain." + loginUserName.Text.Split('\\')[0] + ".com",
                        loginUserName.Text, loginPassword.Text);


                var dirSearch = new DirectorySearcher(entry,
                    "(&(objectCategory=person)(objectClass=user)(SAMAccountname=" + loginUserName.Text.Split('\\')[1] + "))");
                var user = dirSearch.FindOne();
                var displayname = user.Properties["displayname"][0];
                string email = displayname.ToString().Trim().Replace(' ', '.') + "@domain.com";

                MailMessage mail = new MailMessage();
                mail.To.Add(email);
                mail.Subject = "Site details for " + DomainName.Text;
                mail.Body = TxtOutput.Text;
                mail.From = new MailAddress("SiteCreator@domain.com");
                SmtpClient smtp = new SmtpClient(getConfigSections("EmailServer"));
                smtp.Send(mail);
            }
            catch (Exception err)
            {
                WriteOut("Email Error: " + err);
            }
        }

        public void Logins(String domainName)
        {
            var w = new Regex("^www\\.");
            var nz = new Regex(".co.nz$");
            var au = new Regex(".com.au$");
            var com = new Regex(".com$");
            var net = new Regex(".net$");
            var eduA = new Regex(".edu.au$");
            var netA = new Regex(".net.au$");
            var org = new Regex(".org$");
            var orgA = new Regex(".org.au$");

            Regex[] foldersRegex = { w, nz, au, com, net, eduA, netA, org, orgA };

            domainName = foldersRegex.Aggregate(domainName, (current, pattern) => pattern.Replace(current, ""));


            var segments = domainName.Split('.');
            int numFullStops = segments.Length - 1;
            int maxChars = 16 - numFullStops;

            int userNameLength = domainName.Length;

            if (userNameLength <= 16)
            {
                userName = domainName.Replace('.', '_');
            }
            else
            {
                int leftoverChars = 0;
                for (int i = 0; i < segments.Length; i++)
                {
                    int lengthOfSegment;
                    int charPerSegment = maxChars / segments.Length;
                    if (segments[i].Length < charPerSegment)
                    {
                        lengthOfSegment = segments[i].Length;
                        leftoverChars = charPerSegment - segments[i].Length;
                    }
                    else
                    {
                        lengthOfSegment = charPerSegment + leftoverChars;
                    }
                    userName += segments[i].Substring(0, lengthOfSegment);

                    if (i < numFullStops)
                    {
                        userName += "_";
                    }
                }
            }

            FTPusername = "FTP_" + userName;
            FTPpassword = Password(8);

            IISusername = "IIS_" + userName;
            IISpassword = Password(8);

            TxtOutput.Text += "\nFTP: " + FTPusername + " | " + FTPpassword;
            TxtOutput.Text += "\nIIS: " + IISusername + " | " + IISpassword;

        }

        public String Password(int length)
        {
            System.Threading.Thread.Sleep(500);
            //Done this way because web configs can only accept specific subsets of symbols for db creds
            const string chars = "abcdefghijklmnopqrstuvwxyz!#%&ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            const string nums = "0123456789";
            var random = new Random();

            var result = new string(
                Enumerable.Repeat(chars, length)
                          .Select(s => s[random.Next(s.Length)])
                          .ToArray());

            var number = new string(
                Enumerable.Repeat(nums, 1)
                          .Select(s => s[random.Next(s.Length)])
                          .ToArray());

            result += number;
            return result;
        }

        public void ActiveDirectorySetup(bool overwrite)
        {
            const string ftpDetails = "OU=Users,OU=";
            const string iisDetails = "OU=";
            String[] siteTypes = { iisDetails, ftpDetails };

            foreach (String type in siteTypes)
            {
                String siteConnection = type;
                String siteUsername;
                String sitePassword;
                if (type == iisDetails)
                {
                    siteUsername = IISusername;
                    sitePassword = IISpassword;
                }
                else
                {
                    siteUsername = FTPusername;
                    sitePassword = FTPpassword;
                }

                using (var de = new DirectoryEntry(getConfigSections("ADServer") + "/" + siteConnection + ",DC= " + loginUserName.Text.Split('\\')[0] + ",DC=net", loginUserName.Text, loginPassword.Text))
                {
                    bool creatingNewUser = false;
                    try
                    {
                        using (var dirSearch = new DirectorySearcher(de, "(&(objectClass=user)(name=" + siteUsername + "))", new[] { "cn" }))
                        {
                            de.RefreshCache();
                            SearchResult result = dirSearch.FindOne();
                            if (result != null && !overwrite)
                            {
                                WriteOut("User with that name already exists. Please enter a unique domain name. If you want to override the existing entries, select the Override checkbox.");
                            }
                            else if (overwrite)
                            {
                                WriteOut("Overwriting existing user.");
                                creatingNewUser = true;
                            }
                            else
                            {
                                WriteOut("No user with that name.");
                                creatingNewUser = true;
                            }

                        }
                    }
                    catch (Exception e)
                    {
                        WriteOut("Failed because of: " + e);
                        creatingNewUser = false;
                    }
                    if (creatingNewUser)
                    {
                        try
                        {
                            if (overwrite)
                            {
                                DirectoryEntry oldUser = de.Children.Find("CN=" + siteUsername, "user");
                                de.Children.Remove(oldUser);
                                WriteOut("Removed existing user entry.");
                            }

                            DirectoryEntry user = de.Children.Add("CN=" + siteUsername, "user");
                            user.Properties["sAMAccountName"].Add(siteUsername);
                            user.Properties["userPrincipalName"].Value = siteUsername + "@" + loginUserName.Text.Split('\\')[0] + ".com";
                            user.CommitChanges();
                            WriteOut("Added new user.");

                            user.Invoke("SetPassword", new Object[] { sitePassword });
                            user.Properties["userAccountControl"].Value = 0x10240; //Password never expires (0x10000) and normal account (0x200) + can't change password (0x40)
                            user.CommitChanges();
                            WriteOut("Set user password and password never expires flag.");
                            de.CommitChanges();

                            //REDO TO USE THE DIRECTORY SERVICES ACCOUNT MANAGEMENT STUFF
                            using (var pc = new PrincipalContext(ContextType.Domain, "servername." + loginUserName.Text.Split('\\')[0] + ".net", "OU=,DC=" + loginUserName.Text.Split('\\')[0] + ",DC=net", loginUserName.Text, loginPassword.Text))
                            {
                                GroupPrincipal group = GroupPrincipal.FindByIdentity(pc, "WWWRoot-" + folderGroup);
                                PrincipalContext mainContext = new PrincipalContext(ContextType.Domain, "servername." + loginUserName.Text.Split('\\')[0] + ".com", siteConnection + ",DC=" + loginUserName.Text.Split('\\')[0] + ",DC=com", loginUserName.Text, loginPassword.Text);
                                group.Members.Add(mainContext, IdentityType.UserPrincipalName, siteUsername + "@" + loginUserName.Text.Split('\\')[0] + ".com");
                                group.Save();
                                mainContext.Dispose();
                            }

                            //USER CAN'T CHANGE PASSWORD FLAG NOT SETTING
                            ActiveDirectorySecurity adSec = de.ObjectSecurity;

                            var securityDescriptor = adSec.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                            var testSD = adSec.GetSecurityDescriptorBinaryForm();
                            var sid = new SecurityIdentifier(WellKnownSidType.SelfSid, null);
                            //TxtOutput.Text += "SDDL: " + securityDescriptor + "| Binary: " + testSD;

                            Guid changePasswordGuid = new Guid("{ab721a53-1e2f-11d0-9819-00aa0040529b}");
                            RawSecurityDescriptor rawSecDes = new RawSecurityDescriptor(securityDescriptor);
                            var rawAcl = rawSecDes.DiscretionaryAcl;
                            DiscretionaryAcl discACL = new DiscretionaryAcl(false, true, rawAcl);
                            discACL.SetAccess(AccessControlType.Deny, sid, 0x10000000, InheritanceFlags.None, PropagationFlags.None, ObjectAceFlags.ObjectAceTypePresent, changePasswordGuid, changePasswordGuid);

                            de.CommitChanges();

                        }
                        catch (Exception e)
                        {
                            WriteOut("Failed for reasons:" + e);
                        }
                    }
                }
            }
        }

        public void Permissions()
        {
            DirectoryInfo folderDirInfo = new DirectoryInfo(folderPath);
            DirectoryInfo logDirInfo = new DirectoryInfo(logPath);

            DirectorySecurity folderSec = folderDirInfo.GetAccessControl();
            DirectorySecurity logSec = logDirInfo.GetAccessControl();

            var server1 = new NTAccount(ServerName.Text + "$");
            var server2 = new NTAccount(ServerName.Text + "$");

            var IIS = new FileSystemAccessRule(IISusername, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var FTP = new FileSystemAccessRule(FTPusername, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var server1rule = new FileSystemAccessRule(server1, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var server2rule = new FileSystemAccessRule(server2, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var serverAdmin = new FileSystemAccessRule("ADMINISTRATORS", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var system = new FileSystemAccessRule("SYSTEM", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var logFile = new FileSystemAccessRule("LogFile-" + folderGroup, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);
            var admin = new FileSystemAccessRule("Administrators", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow);

            FileSystemAccessRule[] siteRules = { IIS, FTP, serverAdmin, system, admin };
            FileSystemAccessRule[] logRules = { server1rule, server2rule, serverAdmin, system, logFile, admin };
            FileSystemAccessRule[][] rules = { siteRules, logRules };

            logSec.SetAccessRuleProtection(true, false);

            foreach (var array in rules)
            {
                foreach (var accessRule in array)
                {
                    if (array == siteRules)
                    {
                        try
                        {
                            folderSec.AddAccessRule(accessRule);
                        }
                        catch (Exception e)
                        {
                            TxtOutput.Text += "A site rule failed with the exception: " + e;
                        }
                    }
                    try
                    {
                        logSec.AddAccessRule(accessRule);
                    }
                    catch (Exception e)
                    {
                        TxtOutput.Text += "A log rule failed with the exception: " + e;
                    }
                }
            }
            folderDirInfo.SetAccessControl(folderSec);
            logDirInfo.SetAccessControl(logSec);
        }

        public void MakeAnIIS(String domainName)
        {
            IntPtr userToken = IntPtr.Zero;

            bool success = LogonUser(
              loginUserName.Text.Split('\\')[1], loginUserName.Text.Split('\\')[0], loginPassword.Text,
             LOGON32_LOGON_NETWORK_CLEARTEXT,//2,
              0, //0
              out userToken);

            if (!success)
            {
                throw new SecurityException("Logon user failed");
            }

            using (WindowsIdentity.Impersonate(userToken))
            {
                //MUST BE ON REMOTE COMPUTER ServerName.Text
                ServerManager serverManager = ServerManager.OpenRemote(ServerName.Text);

                using (serverManager)
                {
                    try
                    {
                        //Application Pool
                        ApplicationPool newPool = serverManager.ApplicationPools.Add(domainName);

                        newPool.ProcessModel.IdentityType = ProcessModelIdentityType.SpecificUser;
                        newPool.ProcessModel.UserName = loginUserName.Text.Split('\\')[0] + "\\" + IISusername;
                        newPool.ProcessModel.Password = IISpassword;

                        serverManager.CommitChanges();
                        TxtOutput.Text += "Added application pool";

                        //Site
                        var siteInfo = serverManager.Sites.CreateElement();
                        siteInfo.SetAttributeValue("name", domainName);
                        siteInfo.Id = serverManager.Sites.Max(i => i.Id) + 1;
                        siteInfo.ApplicationDefaults.ApplicationPoolName = domainName;
                        serverManager.Sites.AddAt(0, siteInfo);
                        serverManager.CommitChanges();
                        TxtOutput.Text += "Created site";

                        //Physical path
                        var iisSite = serverManager.Sites[domainName];
                        iisSite.Applications.Add("/", null);
                        serverManager.CommitChanges();

                        var apps = serverManager.Sites[domainName].Applications[0];
                        apps.VirtualDirectories[0].PhysicalPath = folderPath;
                        serverManager.CommitChanges();
                        TxtOutput.Text += "Set physical path";

                        //Bindings
                        BindingCollection bindingCollection = serverManager.Sites[domainName].Bindings;
                        Microsoft.Web.Administration.Binding binding = bindingCollection.CreateElement("binding");
                        binding["protocol"] = "http";
                        binding["bindingInformation"] = @"*:80:" + domainName;
                        bindingCollection.AddAt(0, binding);
                        serverManager.CommitChanges();
                        TxtOutput.Text += "Set bindings";

                        //Credentials
                        var virtDir = serverManager.Sites[domainName].Applications[0].VirtualDirectories[0];
                        virtDir.Attributes["username"].Value = loginUserName.Text.Split('\\')[0] + "\\" + IISusername;
                        virtDir.Attributes["password"].Value = IISpassword;
                        serverManager.CommitChanges();
                        TxtOutput.Text += "Set Username and Password";

                        //Log flags
                        var siteLogs = serverManager.Sites[domainName];
                        siteLogs.LogFile.Directory = logPath;
                        siteLogs.LogFile.Enabled = true;
                        siteLogs.LogFile.LogExtFileFlags =
                            LogExtFileFlags.BytesRecv &
                            LogExtFileFlags.BytesSent &
                            LogExtFileFlags.ClientIP &
                            LogExtFileFlags.ComputerName &
                            LogExtFileFlags.Date &
                            LogExtFileFlags.Host &
                            LogExtFileFlags.HttpStatus &
                            LogExtFileFlags.HttpSubStatus &
                            LogExtFileFlags.Method &
                            LogExtFileFlags.ProtocolVersion &
                            LogExtFileFlags.Referer &
                            LogExtFileFlags.ServerIP &
                            LogExtFileFlags.ServerPort &
                            LogExtFileFlags.SiteName &
                            LogExtFileFlags.Time &
                            LogExtFileFlags.TimeTaken &
                            LogExtFileFlags.UriQuery &
                            LogExtFileFlags.UriStem &
                            LogExtFileFlags.UserAgent &
                            LogExtFileFlags.UserName &
                            LogExtFileFlags.Win32Status;
                        serverManager.CommitChanges();
                        TxtOutput.Text += "Set logging flags";
                    }
                    catch (Exception e)
                    {
                        TxtOutput.Text += "Failed because: " + e;
                    }
                    TxtOutput.Text += "Finished IIS creation";
                }
            }
        }

        public void MakeAnFTP(String domainName)
        {
            //MUST BE ON REMOTE COMPUTER

            IntPtr userToken = IntPtr.Zero;

            bool success = LogonUser(
              loginUserName.Text.Split('\\')[1], loginUserName.Text.Split('\\')[0], loginPassword.Text,
             LOGON32_LOGON_NETWORK_CLEARTEXT,//2,
              0, //0
              out userToken);

            if (!success)
            {
                throw new SecurityException("Logon user failed");
            }
            System.Security.Principal.WindowsIdentity.GetCurrent();
            using (WindowsIdentity.Impersonate(userToken))
            {
                ServerManager serverManager = ServerManager.OpenRemote(ServerName.Text);
                using (serverManager)
                {
                    try
                    {

                        Site ftpSite;
                        //Check if the FTP folder/site exists yet
                        Site serverFolder = serverManager.Sites["FTP"];
                        if (serverFolder == null)
                        {
                            //If it doesn't, create it and set properties (App pool - DefaultAppPool, basicAuth enabled, ssl contorlchannelpolicy 0, ssl datachannelpolicy 0)
                            ftpSite = serverManager.Sites.Add("FTP", @"c:\inetpub\ftproot", 80);
                            ftpSite.ApplicationDefaults.ApplicationPoolName = "DefaultAppPool";
                            Microsoft.Web.Administration.Configuration config =
                                serverManager.GetApplicationHostConfiguration();

                            Microsoft.Web.Administration.ConfigurationSection basicAuth =
                                config.GetSection("system.webServer/security/authentication/basicAuthentication",
                                    "FTP");
                            basicAuth["enabled"] = true;

                            Microsoft.Web.Administration.ConfigurationSection sslPolicy =
                                config.GetSection("system.applicationHost/sites");
                            Microsoft.Web.Administration.ConfigurationElement sslElem =
                                sslPolicy.GetChildElement("siteDefaults")
                                    .GetChildElement("ftpServer")
                                    .GetChildElement("security")
                                    .GetChildElement("ssl");
                            sslElem["controlChannelPolicy"] = @"SslAllow";
                            sslElem["dataChannelPolicy"] = @"SslAllow";

                            serverManager.CommitChanges();
                        }
                        else
                        {
                            ftpSite = serverManager.Sites["FTP"];
                        }

                        Microsoft.Web.Administration.VirtualDirectory ftpFolder = null;

                        if (
                            //Escape your slashes!
                            !Directory.Exists(ServerName.Text +
                                              "\\C$\\inetpub\\ftproot\\" + loginUserName.Text.Split('\\')[0]))
                            Directory.CreateDirectory(ServerName.Text +
                                                      "\\C$\\inetpub\\ftproot\\" + loginUserName.Text.Split('\\')[0]);

                        ftpFolder = ftpSite.Applications[0].VirtualDirectories.Add("/" + loginUserName.Text.Split('\\')[0] + "/" + FTPusername,
                            folderPath);

                        ftpFolder.UserName = FTPusername;
                        ftpFolder.Password = FTPpassword;
                        serverManager.CommitChanges();


                        Microsoft.Web.Administration.Configuration ftpConfig =
                            serverManager.GetApplicationHostConfiguration();
                        Microsoft.Web.Administration.ConfigurationSection authorizationSection =
                            ftpConfig.GetSection("system.ftpServer/security/authorization", "FTP");


                        Microsoft.Web.Administration.ConfigurationElementCollection authorizationCollection =
                            authorizationSection.GetCollection();



                        Microsoft.Web.Administration.ConfigurationElement addElement =
                            authorizationCollection.CreateElement("add");
                        addElement["accessType"] = @"Allow";
                        addElement["roles"] = FTPusername;
                        addElement["permissions"] = @"Read, Write";

                        serverManager.CommitChanges();
                        TxtOutput.Text += "FTP Created Succesfully";
                    }
                    catch (Exception e)
                    {
                        TxtOutput.Text += "FTP failed because of: " + e;
                    }
                }
            }
        }

        public void MySQLSetup(String domainName)
        {
            DBname = domainName.Replace(".", "_");
            if (domainName.Length >= 16)
            {
                if (DBname.Substring(0, DBname.IndexOf("_")).Length < 10)
                {
                    var userFirst = DBname.Substring(0, DBname.IndexOf("_"));
                    dbUsername = "mydbu_" + userFirst;
                }
                else
                {
                    var userFirst = DBname.Substring(0, 10);
                    dbUsername = "mydbu_" + userFirst;
                }


            }
            else
            {
                dbUsername = "mydbu_" + DBname;
            }

            dbPassword = Password(8);

            //Connect to Mysql database
            String connectionString = getConfigSections("MySqlServer");
            var mySQLconnection = new MySqlConnection(connectionString);

            if (mySQLconnection.State != ConnectionState.Open)
            {
                try
                {
                    mySQLconnection.Open();
                    String createDB = "CREATE DATABASE `" + DBname + "`";
                    String createUser = "CREATE USER '" + dbUsername + "'@'%'";
                    String setPassword = "SET PASSWORD FOR '" + dbUsername + "'@'%' = PASSWORD('" + dbPassword + "')";
                    String grantPermissions = "GRANT ALL ON " + DBname + ".* TO '" + dbUsername + "'@'%' WITH GRANT OPTION";
                    String[] commands = { createDB, createUser, setPassword, grantPermissions };

                    foreach (String command in commands)
                    {
                        MySqlCommand newComm = new MySqlCommand(command, mySQLconnection);
                        newComm.ExecuteNonQuery();
                    }
                    TxtOutput.Text +=
                      string.Format("Created MySQL DB {0} on Server: {1} with UserName: {2} and Password: {3} ", DBname, getConfigSections("MySqlServer"), dbUsername, dbPassword);
                }
                catch (MySqlException ex)
                {
                    TxtOutput.Text += "Connecting to MySQL Database failed because of: " + ex;
                }
                finally
                {
                    mySQLconnection.Close();

                }
            }
        }

        public void SQlserverSetup(String domainName)
        {
            DBname = domainName.Replace(".", "_");
            dbUsername = "dbu_" + DBname;
            dbPassword = Password(8);

            String connectionString = getConfigSections("SqlServerOneConnectionString");
            var SQLconnection = new SqlConnection(connectionString);

            if (SQLconnection.State != ConnectionState.Open)
            {
                try
                {
                    SQLconnection.Open();
                    String createDB = "CREATE DATABASE " + DBname + ";";
                    string createLogin = "CREATE LOGIN " + dbUsername + " WITH PASSWORD = '" + dbPassword + "', check_policy = off ;";

                    string usemaster = "USE master;";
                    string deny = "deny VIEW any database to [" + dbUsername + "];";
                    string use = "USE " + DBname + ";";
                    string alter = "ALTER AUTHORIZATION ON DATABASE::[" + DBname + "] to [" + dbUsername + "]";
                    String[] commands = { createDB, use, createLogin, usemaster, deny, use, alter };

                    foreach (String command in commands)
                    {
                        SqlCommand newComm = new SqlCommand(command, SQLconnection);
                        newComm.ExecuteNonQuery();
                    }
                    TxtOutput.Text +=
                       string.Format("Created SQL DB {0} on Server: {1} with UserName: {2} and Password: {3} ", DBname, getConfigSections("SqlServerOne"), dbUsername, dbPassword);
                }
                catch (SqlException ex)
                {
                    TxtOutput.Text += "Connecting to SQL Database failed because of: " + ex;
                }
                finally
                {
                    SQLconnection.Close();

                }
            }
        }

        public string getConfigSections(string key)
        {
            var sectionCollection = ConfigurationManager.GetSection("appSettings") as NameValueCollection;
            return sectionCollection[key];
        }

        public void backUpSQL()
        {
            try
            {
                // create instance of SMO Server object
                Server myServer = new Server(getConfigSections("SqlServerOne"));

                // create new instance of "Restore" object    
                Backup backup = new Backup();
                backup.Database = this.DomainName.Text.Replace(".", "_"); // your database name

                // define options       
                backup.Action = BackupActionType.Database;
                backup.Devices.AddDevice(
                    getConfigSections("BackupDevice") + this.DomainName.Text.Replace(".", "_") + ".bak", DeviceType.File);
                backup.BackupSetName = "Database Backup";
                backup.BackupSetDescription = "Database - Full Backup";

                backup.PercentCompleteNotification = 100;
                backup.Initialize = false;

                // define a callback method to show 

                backup.PercentComplete += new PercentCompleteEventHandler(bac_PercentComplete);

                // execute the restore    
                backup.SqlBackup(myServer);
            }
            catch (Exception e)
            {

                TxtOutput.Text += "Connecting to SQL Database failed because of: " + e;
            }
        }

        private void bac_PercentComplete(object sender, PercentCompleteEventArgs e)
        {
            TxtOutput.Text += "BackUp Completed";

            backUpSQLLog();
        }

        public void backUpSQLLog()
        {
            try
            {
                // create instance of SMO Server object
                Server myServer = new Server(getConfigSections("SqlServerOne"));

                // create new instance of "Restore" object    
                Backup backup = new Backup();
                backup.Database = this.DomainName.Text.Replace(".", "_"); // your database name

                // define options       
                backup.Action = BackupActionType.Log;
                backup.Devices.AddDevice(
                    getConfigSections("BackupDevice") + this.DomainName.Text.Replace(".", "_") + ".trn", DeviceType.File);
                backup.BackupSetName = "Logs Backup";
                backup.BackupSetDescription = "Logs - Full Backup";

                backup.PercentCompleteNotification = 100;
                backup.Initialize = false;

                // define a callback method to show progress
                backup.PercentComplete += new PercentCompleteEventHandler(logBac_PercentComplete);

                // execute the restore    
                backup.SqlBackup(myServer);

            }
            catch (Exception e)
            {

                TxtOutput.Text += "Connecting to SQL Database failed because of: " + e;
            }
        }

        private void logBac_PercentComplete(object sender, PercentCompleteEventArgs e)
        {
            TxtOutput.Text += "Log BackUp Completed";

            restoreSQLDB();
        }

        public void restoreSQLDB()
        {
            try
            {

                //this.DomainName.Text;
                // create instance of SMO Server object
                Server myServer = new Server(getConfigSections("SqlServerTwo"));

                // create new instance of "Restore" object    
                Restore res = new Restore();
                res.Database = this.DomainName.Text.Replace(".", "_");  // your database name

                // define options       
                res.Action = RestoreActionType.Database;
                res.Devices.AddDevice(getConfigSections("BackupDevice") + this.DomainName.Text.Replace(".", "_") + ".bak", DeviceType.File);
                res.PercentCompleteNotification = 100;

                res.ReplaceDatabase = false;

                // define a callback method to show progress
                res.PercentComplete += new PercentCompleteEventHandler(res_PercentComplete);
                res.NoRecovery = true;

                // execute the restore    
                res.SqlRestore(myServer);
            }
            catch (Exception e)
            {

                TxtOutput.Text += "Connecting to SQL Database failed because of: " + e;
            }


        }

        private void res_PercentComplete(object sender, PercentCompleteEventArgs e)
        {
            TxtOutput.Text += "Restore Completed";
            restoreSQLDBLog();
        }

        public void restoreSQLDBLog()
        {
            try
            {
                //this.DomainName.Text;
                // create instance of SMO Server object
                Server myServer = new Server(getConfigSections("SqlServerTwo"));

                // create new instance of "Restore" object    
                Restore res = new Restore();
                res.Database = this.DomainName.Text.Replace(".", "_");  // your database name

                // define options       
                res.Action = RestoreActionType.Log;
                res.Devices.AddDevice(getConfigSections("BackupDevice") + this.DomainName.Text.Replace(".", "_") + ".trn", DeviceType.File);
                res.PercentCompleteNotification = 100;

                res.ReplaceDatabase = true;

                // define a callback method to show progress
                res.PercentComplete += new PercentCompleteEventHandler(resLogs_PercentComplete);
                res.NoRecovery = true;

                // execute the restore    
                res.SqlRestore(myServer);
                Database mir = myServer.Databases[this.DomainName.Text.Replace(".", "_")];

                mir.MirroringPartner = "TCP://" + getConfigSections("SqlServerOne") + ".domain:port";
                mir.Alter();

                Server myServerStart = new Server(getConfigSections("SqlServerOne"));
                Database d = myServerStart.Databases[this.DomainName.Text.Replace(".", "_")];

                d.MirroringPartner = "TCP://" + getConfigSections("SqlServerTwo") + ".domain:port";


                d.MirroringWitness = "TCP://" + getConfigSections("SQLWitness") + ".domain:port";
                d.MirroringSafetyLevel = MirroringSafetyLevel.Full;
                d.Alter();

                DBname = this.DomainName.Text.Replace(".", "_");

                dbUsername = "dbu_" + DBname;


                dbPassword = Password(8);


                String connectionString = getConfigSections("SqlServerTwoConnectionString");
                var SQLconnection = new SqlConnection(connectionString);

                if (SQLconnection.State != ConnectionState.Open)
                {
                    try
                    {
                        SQLconnection.Open();

                        string createLogin = "CREATE LOGIN " + dbUsername + " WITH PASSWORD = '" + dbPassword +
                                             "', check_policy = off ;";

                        string usemaster = "USE master;";
                        string deny = "deny VIEW any database to [" + dbUsername + "];";
                        string use = "USE " + DBname + ";";
                        string alter = "ALTER AUTHORIZATION ON DATABASE::[" + DBname + "] to [" + dbUsername + "]";
                        String[] commands = { use, createLogin, usemaster, deny, use, alter };

                        foreach (String command in commands)
                        {
                            SqlCommand newComm = new SqlCommand(command, SQLconnection);
                            newComm.ExecuteNonQuery();
                        }
                        TxtOutput.Text +=
                            string.Format("Created SQL DB {0} on Server: {1} with UserName: {2} and Password: {3} ", DBname,
                                myServer.Name, dbUsername, dbPassword);
                    }
                    catch (SqlException ex)
                    {
                        TxtOutput.Text += "Connecting to SQL Database failed because of: " + ex;
                    }
                    finally
                    {
                        SQLconnection.Close();

                    }
                }
            }
            catch (Exception e)
            {

                TxtOutput.Text += "Connecting to SQL Database failed because of: " + e;
            }
        }

        private void resLogs_PercentComplete(object sender, PercentCompleteEventArgs e)
        {
            TxtOutput.Text += "Restore Completed";
        }

        protected void BtnClear_Click(object sender, EventArgs e)
        {
            DomainName.Text = "";
            loginUserName.Text = "";
            loginPassword.Text = "";
            TxtOutput.Text = "";
            ServerName.Text = "";
            if (!BtnExecuteScript.Enabled)
            {
                BtnExecuteScript.Enabled = true;
            }
        }
    }
}