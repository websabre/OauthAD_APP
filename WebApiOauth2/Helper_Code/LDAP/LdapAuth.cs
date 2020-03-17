using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using System.Data;

namespace WebApiOauth2.Helper_Code.LDAP
{
    public class LdapAuth
    {
    }

    /// Domain Class for LDAP Attributes
    /// </summary>
    public class LDAPAttribute
    {
        public LDAPAttribute() { }
        public int PropertyIndex { get; set; }
        public string PropertyName { get; set; }
        public string PropertyValue { get; set; }
    }

    /// <summary>
    /// Domain Class for LDAP Groups
    /// </summary>
    public class LDAPGroup
    {
        public LDAPGroup() { }
        public LDAPGroup(string ldapGroupName, string ldapGroupDesc = "")
        {
            LDAPGroupName = ldapGroupName;
            LDAPGroupDesc = ldapGroupDesc;
        }

        public LDAPGroup(string ldapGroupName, string ldapGroupId = null, string ldapGroupDesc = "")
        {
            LDAPGroupId = ldapGroupId;
            LDAPGroupName = ldapGroupName;
            LDAPGroupDesc = ldapGroupDesc;
        }

        public LDAPGroup(string ldapGroupName, string ldapGroupDesc = "", List<LDAPGroup> ldapGroups = null, string ldapGroupId = null)
        {
            LDAPGroupId = ldapGroupId;
            LDAPGroupName = ldapGroupName;
            LDAPGroupDesc = ldapGroupDesc;
            LDAPGroups = ldapGroups;
        }

        public string LDAPGroupId { get; set; }
        public string LDAPGroupName { get; set; }
        public string LDAPGroupDesc { get; set; }
        public bool IsGroup { get; set; }
        public long? Id { get; set; }
        public List<LDAPGroup> LDAPGroups { get; set; }
    }

    /// <summary>
    /// LDAP Authentication Utility class
    /// </summary>
    public class LDAPAuthentication
    {
        public delegate void LoggedDelegate(string name, bool isWindowsAuth = false);
        public static event LoggedDelegate Logged = null;

        #region Local Variables

        private readonly string _path = string.Empty;
        private readonly string _actualpath = string.Empty;
        private readonly string _filterAttribute = string.Empty;
        private readonly string _ldapUserName = string.Empty;
        private readonly string _ldapPassword = string.Empty;

        #endregion

        /// <summary>
        /// Is LDAP Configured or not
        /// </summary>
        /// <returns></returns>
        public static bool IsLDAPConfigured()
        {
            bool _isLDAPConfigured = false;
            if (ConfigurationManager.AppSettings["CurrentAuthMode"] != null
                && !string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings["CurrentAuthMode"])
                && Convert.ToString(ConfigurationManager.AppSettings["CurrentAuthMode"]) == "Windows")
            {
                _isLDAPConfigured = true;
            }
            return _isLDAPConfigured;
        }

        /// <summary>
        /// Customized constructor with path parameter. If path is empty then get from configuration
        /// </summary>
        /// <param name="ldappath">LDAP query path</param>
        public LDAPAuthentication(string ldappath, string ldapUserName, string ldapPassword = null)
        {
            _path = (string.IsNullOrWhiteSpace(ldappath) ? ldappath : (Convert.ToString(ldappath[ldappath.Length - 1]) == @"/" ? ldappath.Substring(0, ldappath.Length - 1).ToUpper() : ldappath.ToUpper()));
            _actualpath = _path;
            _ldapUserName = ldapUserName;
            _ldapPassword = ldapPassword;
        }

        /// <summary>
        /// Changing value in Appsettings.config of key PreviousAuthMode of previous authenication mode 
        /// </summary>
        /// <param name="CurrentMode"></param>
        public static void SettingCurrentAuthenicationMode(string CurrentMode)
        {
            try
            {
                Configuration webconfig = WebConfigurationManager.OpenWebConfiguration("~");
                webconfig.AppSettings.Settings.Remove("CurrentAuthMode");
                webconfig.AppSettings.Settings.Add("CurrentAuthMode", CurrentMode);
                webconfig.Save();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// Changing value in Appsettings.config of key CurrentAuthMode of current authenication mode 
        /// </summary>
        /// <param name="CurrentMode"></param>
        public static void SettingPreviousAuthenicationMode(string CurrentMode)
        {
            try
            {
                Configuration webconfig = WebConfigurationManager.OpenWebConfiguration("~");
                webconfig.AppSettings.Settings.Remove("PreviousAuthMode");
                webconfig.AppSettings.Settings.Add("PreviousAuthMode", CurrentMode);
                webconfig.Save();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// Capturing value in Appsettings.config of key CurrentAuthMode of current authenication mode 
        /// </summary>
        /// <returns></returns>
        public static string CurrentAuthenicationMode()
        {
            if (string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings["CurrentAuthMode"]))
            {
                ConfigurationManager.AppSettings["CurrentAuthMode"] = "Forms";
            }
            return Convert.ToString(ConfigurationManager.AppSettings["CurrentAuthMode"]);
        }

        /// <summary>
        /// Capturing value in Appsettings.config of key PreviousAuthMode of previous authenication mode
        /// </summary>
        /// <returns></returns>
        public static string PreviousAuthenicationMode()
        {
            if (string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings["PreviousAuthMode"]))
            {
                ConfigurationManager.AppSettings["PreviousAuthMode"] = "Forms";
            }
            return Convert.ToString(ConfigurationManager.AppSettings["PreviousAuthMode"]);
        }

        /// <summary>
        /// Changing Authenication mode in web.config
        /// </summary>
        /// <param name="mode"></param>
        public static void ChangeAuthenicationMode(AuthenticationMode mode)
        {
            string isChangedTo = null;
            try
            {
                Configuration webconfig = WebConfigurationManager.OpenWebConfiguration("~");
                SystemWebSectionGroup sysweb = (SystemWebSectionGroup)webconfig.GetSectionGroup("system.web");
                if (sysweb.Authentication.Mode != AuthenticationMode.Windows && mode == AuthenticationMode.Windows)
                {
                    sysweb.Authentication.Mode = AuthenticationMode.Windows;
                    isChangedTo = "Windows";
                }
                else if (sysweb.Authentication.Mode != AuthenticationMode.Forms && mode == AuthenticationMode.Forms)
                {
                    sysweb.Authentication.Mode = AuthenticationMode.Forms;
                    isChangedTo = "Forms";
                }
                webconfig.Save();

                if (!string.IsNullOrWhiteSpace(isChangedTo))
                {
                    HttpContext.Current.Application["CurrentMode"] = isChangedTo;
                    if (HttpContext.Current.Application["PreviousMode"] == null)
                    {
                        HttpContext.Current.Application["PreviousMode"] = isChangedTo;
                    }
                }
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// To Authenicate user using LDAP path
        /// </summary>
        /// <param name="domain">Domain Name</param>
        /// <param name="username">User Name</param>
        /// <param name="pwd">Password</param>
        /// <returns>on success returns true</returns>
        public bool IsAuthenticated(string domain, string username, string pwd)
        {
            string domainAndUsername = domain + @"\" + username;
            return IsAuthenticated(domainAndUsername, pwd);
        }

        /// <summary>
        /// To Authenicate user using LDAP path
        /// </summary>
        /// <param name="domainAndUsername">Domain\User Name or User Name</param>
        /// <param name="pwd">Password of the user</param>
        /// <returns>on success returns true</returns>
        public bool IsAuthenticated(string username, string password = null)
        {
            DirectoryEntry entry = null;
            bool isAuthenticated = false;
            try
            {
                if (string.IsNullOrWhiteSpace(password))
                {
                    if (string.IsNullOrWhiteSpace(_ldapPassword))
                    {
                        entry = new DirectoryEntry(_path);
                    }
                    else
                    {
                        entry = new DirectoryEntry(_path, _ldapUserName, _ldapPassword);
                    }
                }
                else
                {
                    entry = new DirectoryEntry(_path, username, password);
                }

                //Bind to the native AdsObject to force authentication.
                if (entry == null || entry.NativeObject == null)
                {
                    return false;
                }

                DirectorySearcher search = new DirectorySearcher(entry)
                {
                    Filter = "(SAMAccountName=" + username + ")"
                };
                search.PropertiesToLoad.Add("cn");
                SearchResult result = search.FindOne();

                if (null == result)
                {
                    return isAuthenticated;
                }
                isAuthenticated = true;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return isAuthenticated;
        }

        /// <summary>
        /// Validate the user and cookie's maintainace
        /// </summary>
        /// <param name="domainAndUsername">User Name with or without domain name</param>
        /// <param name="pwd">Password of the user</param>
        /// <returns></returns>
        public bool AuthenticateAndMakeAsLoginUser(string domainAndUsername, string pwd, bool isCookiePersistent = false)
        {
            bool isValidUser = false;
            DirectoryEntry entry = new DirectoryEntry(_path, domainAndUsername, pwd);
            try
            {
                //Bind to the native AdsObject to force authentication.
                object obj = entry.NativeObject;
                DirectorySearcher search = new DirectorySearcher(entry)
                {
                    Filter = "(SAMAccountName=" + domainAndUsername + ")"
                };
                search.PropertiesToLoad.Add("cn");
                SearchResult result = search.FindOne();

                if (null == result)
                {
                    return false;
                }

                string _memberfilterAttribute = (string)result.Properties["cn"][0];
                List<string> _membergroups = GetMemberGroupsByUser(_memberfilterAttribute);

                #region Cookie Operation

                FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket(1, domainAndUsername, DateTime.Now, DateTime.Now.AddMinutes(FormsAuthentication.Timeout.Minutes), isCookiePersistent,
                    (_membergroups != null && _membergroups.Count() > 0 ? string.Join("|", _membergroups.ToArray<string>()) : string.Empty));

                //Encrypt the ticket.
                string encryptedTicket = FormsAuthentication.Encrypt(authTicket);

                //Create a cookie, and then add the encrypted ticket to the cookie as data.
                HttpCookie authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);

                if (true == isCookiePersistent)
                {
                    authCookie.Expires = authTicket.Expiration;
                }

                //Add the cookie to the outgoing cookies collection.
                HttpContext.Current.Response.Cookies.Add(authCookie);

                #endregion
                isValidUser = true;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return isValidUser;
        }

        /// <summary>
        /// Validate the user and cookie's maintainace
        /// </summary>
        /// <param name="domainAndUsername">User Name with or without domain name</param>
        /// <param name="pwd">Password of the user</param>
        /// <returns></returns>
        public bool AuthenticateWithUserName(string domainAndUsername, string pwd = null, bool isCookiePersistent = false)
        {
            bool isValidUser = false;
            DirectoryEntry entry = GetDirectoryEntry(null, domainAndUsername, pwd); // new DirectoryEntry(_path, domainAndUsername, pwd);
            try
            {
                //Bind to the native AdsObject to force authentication.
                object obj = entry.NativeObject;
                DirectorySearcher search = new DirectorySearcher(entry)
                {
                    Filter = "(SAMAccountName=" + domainAndUsername + ")"
                };
                search.PropertiesToLoad.Add("cn");
                SearchResult result = search.FindOne();

                if (null == result)
                {
                    return false;
                }

                string _memberfilterAttribute = (string)result.Properties["cn"][0];
                List<string> memberGroups = GetMemberGroupsByUser(_memberfilterAttribute);

                #region Cookie Operation

                FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket(1, domainAndUsername, DateTime.Now, DateTime.Now.AddMinutes(FormsAuthentication.Timeout.Minutes), isCookiePersistent,
                    (memberGroups != null && memberGroups.Count() > 0 ? string.Join("|", memberGroups.ToArray<string>()) : string.Empty));

                //Encrypt the ticket.
                string encryptedTicket = FormsAuthentication.Encrypt(authTicket);

                //Create a cookie, and then add the encrypted ticket to the cookie as data.
                HttpCookie authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);

                if (true == isCookiePersistent)
                {
                    authCookie.Expires = authTicket.Expiration;
                }

                //Add the cookie to the outgoing cookies collection.
                HttpContext.Current.Response.Cookies.Add(authCookie);

                #endregion
                isValidUser = true;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return isValidUser;
        }

        /// <summary>
        /// Get all groups of the user
        /// </summary>
        /// <param name="username"></param>
        /// <param name="pwd">Password of the user</param>
        /// <returns>List of groups</returns>
        public List<string> GetMemberGroups(string username)
        {
            DirectoryEntry entry = new DirectoryEntry(_path, _ldapUserName, _ldapPassword);
            List<string> _groups = null;
            try
            {
                //Bind to the native AdsObject to force authentication.
                object obj = entry.NativeObject;
                DirectorySearcher search = new DirectorySearcher(entry)
                {
                    Filter = "(SAMAccountName=" + username + ")"
                };
                search.PropertiesToLoad.Add("cn");
                SearchResult result = search.FindOne();
                if (null != result)
                {
                    _groups = GetMemberGroupsByUser((string)result.Properties["cn"][0]);
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return _groups;
        }

        /// <summary>
        /// To get groups by user filter
        /// </summary>
        /// <param name="_memberfilterAttribute">filter query</param>
        /// <returns>List of groups</returns>
        public List<string> GetMemberGroupsByUser(string _userName)
        {
            DirectoryEntry entry = null;
            DirectorySearcher search = null;
            List<string> groupNames = new List<string>();
            try
            {
                entry = GetDirectoryEntry(_actualpath, _ldapUserName, _ldapPassword);
                if (entry != null)
                {
                    search = new DirectorySearcher(entry);
                    //{
                    //    Filter = "(SAMAccountName=" + _userName + ")"
                    //};
                    search.PropertiesToLoad.Add("memberOf");
                    SearchResultCollection _resultset = search.FindAll();
                    foreach (SearchResult result in _resultset)
                    {
                        int propertyCount = result.Properties["memberOf"].Count;
                        string dn = string.Empty;
                        int equalsIndex, commaIndex;
                        for (int propertyCounter = 0; propertyCounter < propertyCount; propertyCounter++)
                        {
                            dn = (string)result.Properties["memberOf"][propertyCounter];
                            equalsIndex = dn.IndexOf("=", 1);
                            commaIndex = dn.IndexOf(",", 1);

                            if (-1 == equalsIndex)
                            {
                                return null;
                            }

                            groupNames.Add(dn.Substring((equalsIndex + 1), (commaIndex - equalsIndex) - 1));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return groupNames;
        }

        /// <summary>
        /// To get users with group
        /// </summary>
        /// <param name="_memberfilterAttribute">filter query</param>
        /// <returns>List of groups</returns> Ex: Administrators
        public List<string> GetGroupMembersByGroupName(string _groupName)
        {
            DirectoryEntry entry = null;
            DirectorySearcher search = null;
            List<string> groupNames = new List<string>();
            try
            {
                entry = GetDirectoryEntry(_actualpath, _ldapUserName, _ldapPassword);
                search = new DirectorySearcher(entry)
                {
                    Filter = "(&(objectCategory=person)(objectClass=user)(memberOf=*))"
                };
                search.PropertiesToLoad.Add("memberOf");
                search.PropertiesToLoad.Add("name");
                search.PropertiesToLoad.Add("samaccountname");
                SearchResultCollection resultset = search.FindAll();

                foreach (SearchResult result in resultset)
                {
                    foreach (string prop in result.Properties["memberOf"])
                    {
                        if (prop.Contains(_groupName))
                        {
                            if (result.Properties["samaccountname"] != null && result.Properties["samaccountname"].Count > 0)
                            {
                                groupNames.Add(Convert.ToString(result.Properties["samaccountname"][0]));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return groupNames;
        }

        /// <summary>
        /// With is used to set cookie
        /// </summary>
        public static void AuthenticateRequest()
        {
            string cookieName = FormsAuthentication.FormsCookieName;
            HttpCookie authCookie = HttpContext.Current.Request.Cookies[cookieName];

            if (null == authCookie)
            {
                //There is no authentication cookie.
                return;
            }

            FormsAuthenticationTicket authTicket = null;
            try
            {
                authTicket = FormsAuthentication.Decrypt(authCookie.Value);
                if (Logged != null && authTicket != null && !string.IsNullOrWhiteSpace(authTicket.Name))
                {
                    Logged(authTicket.Name, IsLDAPConfigured());
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

            if (null == authTicket)
            {
                //Cookie failed to decrypt.
                return;
            }

            //When the ticket was created, the UserData property was assigned a
            //pipe-delimited string of group names.
            string[] groups = authTicket.UserData.Split(new char[] { '|' });
            //Create an Identity.
            GenericIdentity id = new GenericIdentity(authTicket.Name, "LdapAuthentication");
            //This principal flows throughout the request.
            GenericPrincipal principal = new GenericPrincipal(id, groups);
            HttpContext.Current.User = principal;
        }

        /// <summary>
        /// Searching types is by group or user
        /// </summary>
        public enum FilterType
        {
            group,
            user
        }

        /// <summary>
        /// To get all users by searchstring as user and same of groups with respective
        /// </summary>
        /// <param name="searchString">filter by user or group option</param>
        /// <returns>list based on search type</returns>
        public List<string> FindAllByType(FilterType searchString)
        {
            List<string> result = new List<string>();
            DirectoryEntry objADAM = default(DirectoryEntry);
            // Binding object. 
            DirectoryEntry objGroupEntry = default(DirectoryEntry);
            // Group Results. 
            DirectorySearcher objSearchADAM = default(DirectorySearcher);
            // Search object. 
            SearchResultCollection objSearchResults = default(SearchResultCollection);
            // Results collection. 

            // Get the AD LDS object. 
            try
            {
                objADAM = GetDirectoryEntry(_actualpath, _ldapUserName, _ldapPassword);
                objADAM.RefreshCache();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

            // Get search object, specify filter and scope, 
            // perform search. 
            try
            {
                objSearchADAM = new DirectorySearcher(objADAM)
                {
                    Filter = "(&(objectCategory=" + Convert.ToString(searchString) + "))"
                };
                objSearchADAM.PropertiesToLoad.Add("name");
                objSearchADAM.PropertiesToLoad.Add("sn");
                objSearchADAM.PropertiesToLoad.Add("SAMAccountName");
                objSearchADAM.SearchScope = SearchScope.Subtree;
                objSearchResults = objSearchADAM.FindAll();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

            // Enumerate groups 
            try
            {
                if (objSearchResults.Count != 0)
                {
                    foreach (SearchResult objResult in objSearchResults)
                    {
                        if (searchString == FilterType.group)
                        {
                            objGroupEntry = objResult.GetDirectoryEntry();
                            result.Add(objGroupEntry.Name);
                        }
                        else
                        {
                            if (objResult.Properties["SAMAccountName"] != null && objResult.Properties["SAMAccountName"].Count > 0)
                            {
                                result.Add(Convert.ToString(objResult.Properties["SAMAccountName"][0]));
                            }
                        }
                    }
                }
                else
                {

                    
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (objGroupEntry != null)
                {
                    objGroupEntry.Close();
                }
                if (objADAM != null)
                {
                    objADAM.Close();
                }
            }
            return result;
        }

        /// <summary>
        /// Get all attributes as per parameters or instance
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="username"></param>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public List<LDAPAttribute> GetAllAttributes(string username = null, string pwd = null, string ldapPath = null)
        {
            List<LDAPAttribute> _attributes = null;
            ldapPath = (string.IsNullOrWhiteSpace(ldapPath) ? ldapPath : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper()));
            try
            {
                DirectoryEntry entry = null;
                entry = GetDirectoryEntry(ldapPath, username, pwd);
                int i = 0;
                if (entry != null && entry.Properties != null && entry.Properties.Count > 0)
                {
                    _attributes = new List<LDAPAttribute>();
                    foreach (PropertyValueCollection property in entry.Properties)
                    {
                        if (property != null && property.Count > 0)
                        {
                            foreach (object value in property)
                            {
                                _attributes.Add(new LDAPAttribute() { PropertyIndex = (++i), PropertyName = property.PropertyName, PropertyValue = Convert.ToString(value) });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return _attributes;
        }

        /// <summary>
        /// Get all attributes as per parameters or instance
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="username"></param>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public List<LDAPAttribute> GetAllLDAPAttributes(string ldapPath = null, string username = null, string pwd = null)
        {
            List<LDAPAttribute> LDAPAttributesList = null;
            DirectoryEntry entry = null;
            ldapPath = string.IsNullOrWhiteSpace(ldapPath)
                ? ldapPath
                : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper());

            string[] _compulosoryAttributes =
                new string[] { "sn", "givenName", "middleName", "personalTitle", "employeeID", "employeeNumber", "mail", "ms-DS-UserAccountDisabled", "manager", "jobTitle",
                    "streetAddress", "postOfficeBox", "st", "postalCode", "telephoneNumber", "mobile", "sAMAccountName", "msDS-", "displayName", "CN","description","DN",
                    "homeDrive","name","objectCategory","objectClass","physicalDeliveryOfficeName","userAccountControl","userPrincipalName","c","company","department",
                    "homephone","l","location","ObjectClass","OU","mailNickname","mDBUseDefaults","msExchHomeServerName","proxyAddresses","targetAddress"};
            try
            {
                entry = GetDirectoryEntry(ldapPath, username, pwd);

                int i = 0;
                if (entry != null && entry.Properties != null && entry.Properties.Count > 0)
                {
                    List<string> _properties = (from p in GetAllAttributes() where !_compulosoryAttributes.Contains(p.PropertyName) select p.PropertyName).ToList();
                    foreach (string attr in _compulosoryAttributes)
                    {
                        if (!_properties.Contains(attr))
                        {
                            _properties.Add(attr);
                        }
                    }

                    LDAPAttributesList = new List<LDAPAttribute>();
                    if (string.IsNullOrWhiteSpace(username))
                    {
                        foreach (string property in entry.Properties.PropertyNames)
                        {
                            LDAPAttributesList.Add(new LDAPAttribute()
                            {
                                PropertyIndex = (++i),
                                PropertyName = property,
                                PropertyValue = Convert.ToString((entry.Properties[property] != null && entry.Properties[property].Value != null ? ConvertToString(entry.Properties[property].Value) : string.Empty))
                            });
                        }

                        foreach (string cattr in _compulosoryAttributes)
                        {
                            LDAPAttribute _attr = (from a in LDAPAttributesList where a.PropertyName == cattr select a).FirstOrDefault();
                            if (_attr == null)
                            {
                                LDAPAttributesList.Add(new LDAPAttribute()
                                {
                                    PropertyIndex = (++i),
                                    PropertyName = cattr,
                                    PropertyValue = Convert.ToString((entry.Properties[cattr] != null && entry.Properties[cattr].Value != null ? ConvertToString(entry.Properties[cattr].Value) : string.Empty))
                                });
                            }
                        }
                    }
                    else
                    {
                        #region LDAP Compulsory Properties
                        DirectorySearcher _dirSearcher = new DirectorySearcher(entry)
                        {
                            Filter = "(cn=" + (username ?? _ldapUserName) + ")"
                        };

                        _dirSearcher.PropertiesToLoad.AddRange(_properties.ToArray());
                        _dirSearcher.PageSize = 1000;
                        _dirSearcher.SearchScope = SearchScope.Subtree;
                        SearchResultCollection _resultset = _dirSearcher.FindAll();

                        if (_resultset != null)
                        {
                            int _index = 0;
                            foreach (SearchResult _result in _resultset)
                            {
                                foreach (string property in _result.Properties.PropertyNames)
                                {
                                    bool _iscompulsoryProp = false;
                                    foreach (string attr in _compulosoryAttributes)
                                    {
                                        if (_result.Properties.Contains(attr))
                                        {
                                            List<LDAPAttribute> _alreadyExistAttr = (from a in LDAPAttributesList where a.PropertyName == attr select a).ToList();
                                            if (_alreadyExistAttr == null || _alreadyExistAttr.Count() == 0)
                                            {
                                                _iscompulsoryProp = true;
                                                LDAPAttributesList.Add(new LDAPAttribute()
                                                {
                                                    PropertyIndex = _index++,
                                                    PropertyName = attr,
                                                    PropertyValue = Convert.ToString(_result.Properties[attr][0])
                                                });
                                                break;
                                            }
                                        }
                                    }
                                    if (!_iscompulsoryProp)
                                    {
                                        LDAPAttributesList.Add(new LDAPAttribute() { PropertyIndex = (++i), PropertyName = property, PropertyValue = Convert.ToString((_result.Properties[property] != null && _result.Properties[property].Count > 0 && _result.Properties[property][0] != null ? ConvertToString(_result.Properties[property][0]) : string.Empty)) });
                                    }
                                }
                            }
                        }
                        #endregion
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return LDAPAttributesList;
        }

        /// <summary>
        /// Convert to string
        /// </summary>
        /// <param name="_obj"></param>
        /// <returns></returns>
        private string ConvertToString(object _obj)
        {
            string _val = string.Empty;
            try
            {
                Type _objType = _obj.GetType();
                switch (_objType.Name)
                {
                    case "String":
                    case "Int32":
                    case "DateTime":
                    case "Boolean":
                        _val = Convert.ToString(_obj);
                        break;
                    case "Byte[]":
                        SecurityIdentifier sid = new SecurityIdentifier(_obj as byte[], 0);
                        _val = Convert.ToString((sid != null && sid.Value != null ? sid.Value : string.Empty));
                        break;
                    case "Object[]":
                        _val = string.Join(" ", (_obj != null ? (object[])_obj : null));
                        break;
                    case "__ComObject":
                        _val = string.Empty;
                        break;
                    default:
                        _val = string.Empty;
                        break;
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return _val;
        }

        /// <summary>
        /// Get all attributes of the user
        /// </summary>
        /// <param name="User">Give username of which need user's attributes</param>
        /// <param name="loginName">Admin user</param>
        /// <param name="loginpwd">Admin Pass</param>
        /// <param name="ldapPath">LDAP Path</param>
        /// <returns></returns>
        public List<LDAPAttribute> GetAllAttributesOfUser(string User, string loginName = null, string loginpwd = null, string ldapPath = null)
        {
            List<LDAPAttribute> LDAPAttributesList = null;
            DirectoryEntry entry = null;
            ldapPath = string.IsNullOrWhiteSpace(ldapPath)
                ? ldapPath
                : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper());
            try
            {
                entry = GetDirectoryEntry(ldapPath, loginName, loginpwd);

                if (entry != null)
                {
                    string[] _compulosoryAttributes = new string[] { "sn", "givenName", "middleName", "personalTitle", "employeeID", "employeeNumber", "mail",
                        "ms-DS-UserAccountDisabled", "manager", "jobTitle", "streetAddress", "postOfficeBox", "st", "postalCode", "telephoneNumber", "mobile",
                        "sAMAccountName", "msDS-", "displayName", "CN","description","DN","homeDrive","name","objectCategory","objectClass","physicalDeliveryOfficeName",
                        "userAccountControl","userPrincipalName","c","company","department","homephone","l","location","ObjectClass","OU","mailNickname","mDBUseDefaults",
                        "msExchHomeServerName","proxyAddresses","targetAddress"};

                    List<string> _properties = (from p in GetAllAttributes() where !_compulosoryAttributes.Contains(p.PropertyName) select p.PropertyName).ToList();

                    foreach (string attr in _compulosoryAttributes)
                    {
                        if (!_properties.Contains(attr))
                        {
                            _properties.Add(attr);
                        }
                    }

                    DirectorySearcher search = new DirectorySearcher(entry)
                    {
                        Filter = "(SAMAccountName=" + Convert.ToString(User) + ")"
                    };
                    search.PropertiesToLoad.AddRange(_properties.ToArray<string>());
                    SearchResultCollection _resultset = search.FindAll();

                    if (null == _resultset)
                    {
                        return null;
                    }
                    try
                    {
                        #region LDAP Compulsory Properties
                        if (_resultset != null)
                        {
                            int _index = 0;
                            LDAPAttributesList = new List<LDAPAttribute>();
                            foreach (SearchResult _result in _resultset)
                            {
                                foreach (string property in _result.Properties.PropertyNames)
                                {
                                    bool _iscompulsoryProp = false;
                                    foreach (string attr in _compulosoryAttributes)
                                    {
                                        if (_result.Properties.Contains(attr))
                                        {
                                            List<LDAPAttribute> _alreadyExistAttr = (from a in LDAPAttributesList where a.PropertyName == attr select a).ToList();
                                            if ((_alreadyExistAttr == null || _alreadyExistAttr.Count() == 0))
                                            {
                                                _iscompulsoryProp = true;
                                                LDAPAttributesList.Add(new LDAPAttribute()
                                                {
                                                    PropertyIndex = _index++,
                                                    PropertyName = attr,
                                                    PropertyValue = Convert.ToString(_result.Properties[attr][0])
                                                });
                                                break;
                                            }
                                        }
                                    }

                                    if (!_iscompulsoryProp)
                                    {
                                        LDAPAttributesList.Add(new LDAPAttribute() { PropertyIndex = (++_index), PropertyName = property, PropertyValue = Convert.ToString((_result.Properties[property] != null && _result.Properties[property].Count > 0 && _result.Properties[property][0] != null ? ConvertToString(_result.Properties[property][0]) : string.Empty)) });
                                    }
                                }
                            }
                        }
                        #endregion
                    }
                    catch (Exception ex)
                    {
                        throw new Exception(ex.Message);
                    }
                    finally
                    {
                        if (entry != null)
                        {
                            entry.Close();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (entry != null)
                {
                    entry.Close();
                }
            }
            return LDAPAttributesList;
        }

        /// <summary>
        /// Get all group as per parameters or instance
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="username"></param>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public List<LDAPGroup> GetAllGroups(string ldapPath = null, string username = null, string pwd = null)
        {
            DirectoryEntry _de = default(DirectoryEntry);
            DirectorySearcher ds = default(DirectorySearcher);
            List<LDAPGroup> ldapGroups = default(List<LDAPGroup>);
            ldapPath = (string.IsNullOrWhiteSpace(ldapPath) ? ldapPath : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper()));
            try
            {
                _de = GetDirectoryEntry(ldapPath, username, pwd);
                if (_de != null)
                {
                    ds = new DirectorySearcher(_de);
                    if (ds != null)
                    {
                        ds.Filter = "(&(objectClass=group))";
                        ds.SearchScope = SearchScope.Subtree;
                        ds.PageSize = 1000;
                        ds.SizeLimit = 0;
                        SearchResultCollection resultset = ds.FindAll();
                        ldapGroups = new List<LDAPGroup>();
                        List<string> _alreadyAddedLDAPGroups = new List<string>();
                        foreach (SearchResult result in resultset)
                        {
                            DirectoryEntry _de1 = result.GetDirectoryEntry();
                            try
                            {
                                if (_de1.Parent != null)
                                {
                                    DirectoryEntry _de2 = _de1.Parent;
                                    bool _isGroup = false;

                                    LDAPGroup ldapParentGroup = default(LDAPGroup);
                                    LDAPGroup isAlreadyAdded = null;
                                    try
                                    {
                                        isAlreadyAdded = (from g in ldapGroups where g.LDAPGroupName == _de2.Name select g).FirstOrDefault();
                                        if (isAlreadyAdded == null)
                                        {
                                            isAlreadyAdded = (from g in ldapGroups
                                                              select (from sg in g.LDAPGroups
                                                                      where sg.LDAPGroupName == _de2.Name
                                                                      select sg
                                                                      ).FirstOrDefault()
                                                               ).FirstOrDefault();
                                        }

                                        if (isAlreadyAdded == null)
                                        {
                                            isAlreadyAdded = (from g in ldapGroups
                                                              select (from sg in g.LDAPGroups where sg.LDAPGroupName == _de2.Name select sg).FirstOrDefault()).FirstOrDefault();
                                            SecurityIdentifier sid = null;
                                            if (_de2.Properties["objectSid"] != null && _de2.Properties["objectSid"].Count > 0 && _de2.Properties["objectSid"][0] != null)
                                            {
                                                sid = new SecurityIdentifier(_de2.Properties["objectSid"][0] as byte[], 0);
                                            }
                                            ldapParentGroup = new LDAPGroup()
                                            {
                                                LDAPGroupId = Convert.ToString((sid != null ? sid.Value : string.Empty)),
                                                LDAPGroupName = _de2.Name,
                                                LDAPGroupDesc = Convert.ToString((_de2.Properties["description"] != null && _de2.Properties["description"].Count > 0 ? _de2.Properties["description"][0] : string.Empty)),
                                                IsGroup = _isGroup
                                            };
                                            _alreadyAddedLDAPGroups.Add(_de2.Name);
                                        }
                                        else
                                        {
                                            ldapParentGroup = isAlreadyAdded;
                                        }

                                        if (!_alreadyAddedLDAPGroups.Contains(result.GetDirectoryEntry().Name))
                                        {
                                            if (ldapParentGroup.LDAPGroups == null)
                                            {
                                                ldapParentGroup.LDAPGroups = new List<LDAPGroup>();
                                            }

                                            SecurityIdentifier sid = null;
                                            if (result.Properties["objectSid"] != null && result.Properties["objectSid"].Count > 0 && result.Properties["objectSid"][0] != null)
                                            {
                                                sid = new SecurityIdentifier(result.Properties["objectSid"][0] as byte[], 0);
                                            }

                                            ldapParentGroup.LDAPGroups.Add(new LDAPGroup()
                                            {
                                                LDAPGroupId = Convert.ToString((sid != null ? sid.Value : string.Empty)),
                                                LDAPGroupName = result.GetDirectoryEntry().Name,
                                                LDAPGroupDesc = Convert.ToString((result.Properties["description"] != null && result.Properties["description"].Count > 0 ? result.Properties["description"][0] : string.Empty)),
                                                IsGroup = true
                                            });

                                            _alreadyAddedLDAPGroups.Add(result.GetDirectoryEntry().Name);
                                        }

                                        if (isAlreadyAdded == null)
                                        {
                                            ldapGroups.Add(ldapParentGroup);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                       
                                    }
                                    finally
                                    {
                                        if (_de2 != null)
                                        {
                                            _de2.Close();
                                        }
                                    }
                                }
                                else
                                {
                                    if (!_alreadyAddedLDAPGroups.Contains(result.GetDirectoryEntry().Name))
                                    {
                                        SecurityIdentifier sid = null;
                                        if (result.Properties["objectSid"] != null && result.Properties["objectSid"].Count > 0 && result.Properties["objectSid"][0] != null)
                                        {
                                            sid = new SecurityIdentifier(result.Properties["objectSid"][0] as byte[], 0);
                                        }

                                        ldapGroups.Add(new LDAPGroup()
                                        {
                                            LDAPGroupId = Convert.ToString((sid != null ? sid.Value : string.Empty)),
                                            LDAPGroupName = result.GetDirectoryEntry().Name,
                                            LDAPGroupDesc = Convert.ToString((result.Properties["description"] != null && result.Properties["description"].Count > 0 ? result.Properties["description"][0] : string.Empty)),
                                            IsGroup = true
                                        });
                                        _alreadyAddedLDAPGroups.Add(result.GetDirectoryEntry().Name);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                throw new Exception(ex.Message);
                            }
                            finally
                            {
                                if (_de1 != null)
                                {
                                    _de1.Close();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                if (ds != null)
                {
                    ds.Dispose();
                }

                if (_de != null)
                {
                    _de.Close();
                }
            }
            return ldapGroups;
        }

        public class Data
        {
            public Data() { }
            public string title { get; set; }
        }
        public class Attribute
        {
            public Attribute() { }
            public string id { get; set; }
            [DefaultValue("active")]
            public string isactive { get; set; }
            public string sid { get; set; }
            [DefaultValue("")]
            public string psid { get; set; }
            public string title { get; set; }
            [DefaultValue(false)]
            public bool isgroup { get; set; }
            [DefaultValue("myIcon")]
            public string @class { get; set; }
        }
        public class JSTreeNode
        {
            public JSTreeNode() { }
            [DefaultValue("closed")]
            public string state { get; set; }
            public Data data { get; set; }
            public Attribute attr { get; set; }
            [DefaultValue("myIcon")]
            public string icon { get; set; }
            public List<JSTreeNode> children { get; set; }
        }

        /// <summary>
        /// jstree format
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="username"></param>
        /// <param name="pwd"></param>
        /// <returns></returns>
        public List<JSTreeNode> GetAllGroupsForTreeModel(string ldapPath = null, string username = null, string pwd = null)
        {
            List<JSTreeNode> ldapGroupsInTreeModelList = null;
            ldapPath = (string.IsNullOrWhiteSpace(ldapPath) ? ldapPath
                : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper()));
            try
            {
                List<LDAPGroup> _ldapGroups = GetAllGroups(ldapPath, username, pwd);
                if (_ldapGroups != null && _ldapGroups.Count() > 0)
                {
                    long _gindex = 0;
                    ldapGroupsInTreeModelList = (from t in _ldapGroups
                                                 select new JSTreeNode()
                                                 {
                                                     attr = new Attribute()
                                                     {
                                                         id = "TreeGroupIndex_" + (_gindex++).ToString(),
                                                         sid = t.LDAPGroupId,
                                                         title = (string.IsNullOrWhiteSpace(t.LDAPGroupDesc) ? t.LDAPGroupName.Split(new char[] { '=' })[1] : t.LDAPGroupDesc),
                                                         isgroup = t.IsGroup
                                                     },
                                                     data = new Data() { title = t.LDAPGroupName.Split(new char[] { '=' })[1] },
                                                     children = GetAllSubGroupsForTreeModel(ref _gindex, t.LDAPGroups, t.LDAPGroupId)
                                                 }).ToList();
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return ldapGroupsInTreeModelList;
        }

        /// <summary>
        /// LDAP Groups in tree structure
        /// </summary>
        /// <param name="gIndex"></param>
        /// <param name="_ldapGroups"></param>
        /// <param name="psid"></param>
        /// <returns></returns>
        private List<JSTreeNode> GetAllSubGroupsForTreeModel(ref long gIndex, List<LDAPGroup> _ldapGroups, string psid)
        {
            List<JSTreeNode> ldapGroupsInTreeModelList = null;
            try
            {
                long _gIndex = gIndex;
                ldapGroupsInTreeModelList = (from t in _ldapGroups
                                             select new JSTreeNode()
                                             {
                                                 attr = new Attribute()
                                                 {
                                                     id = "TreeGroupIndex_" + (_gIndex++).ToString(),
                                                     sid = t.LDAPGroupId,
                                                     psid = psid,
                                                     title = (string.IsNullOrWhiteSpace(t.LDAPGroupDesc) ? t.LDAPGroupName.Split(new char[] { '=' })[1] : t.LDAPGroupDesc),
                                                     isgroup = t.IsGroup
                                                 },

                                                 data = new Data() { title = t.LDAPGroupName.Split(new char[] { '=' })[1] },
                                                 children = (t.LDAPGroups != null && t.LDAPGroups.Count > 0 ? GetAllSubGroupsForTreeModel(ref _gIndex, t.LDAPGroups, t.LDAPGroupId) : null)
                                             }).ToList();
                gIndex = _gIndex;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return ldapGroupsInTreeModelList;
        }

        /// <summary>
        /// Get Directory Entry
        /// </summary>
        /// <param name="ldapPath"></param>
        /// <param name="username"></param>
        /// <param name="pwd"></param>
        /// <returns></returns>
        private DirectoryEntry GetDirectoryEntry(string ldapPath = null, string username = null, string pwd = null)
        {
            DirectoryEntry _de = null;
            ldapPath = string.IsNullOrWhiteSpace(ldapPath)
                ? ldapPath
                : (Convert.ToString(ldapPath[ldapPath.Length - 1]) == @"/" ? ldapPath.Substring(0, ldapPath.Length - 1).ToUpper() : ldapPath.ToUpper());
            try
            {
                if (!string.IsNullOrWhiteSpace(_actualpath))
                {
                    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(pwd))
                    {
                        if (string.IsNullOrWhiteSpace(_ldapPassword))
                        {
                            _de = new DirectoryEntry(string.IsNullOrWhiteSpace(ldapPath) ? _actualpath : ldapPath);
                        }
                        else
                        {
                            _de = new DirectoryEntry(string.IsNullOrWhiteSpace(ldapPath) ? _actualpath : ldapPath, _ldapUserName, _ldapPassword);
                        }
                    }
                    else
                    {
                        _de = new DirectoryEntry(string.IsNullOrWhiteSpace(ldapPath) ? _actualpath : ldapPath, username, pwd);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            return _de;
        }
    }

}