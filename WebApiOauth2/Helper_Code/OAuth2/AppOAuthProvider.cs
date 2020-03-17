//-----------------------------------------------------------------------
// <copyright file="AppOAuthProvider.cs" company="None">
//     Copyright (c) Allow to distribute this code.
// </copyright>
// <author>Asma Khalid</author>
//-----------------------------------------------------------------------

namespace WebApiOauth2.Helper_Code.OAuth2
{
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OAuth;
    using Models;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web;
    using System.DirectoryServices;
    using WebApiOauth2.Helper_Code.LDAP;
    /// <summary>
    /// Application OAUTH Provider class.
    /// </summary>
    public class AppOAuthProvider : OAuthAuthorizationServerProvider
    {
        #region Private Properties

        /// <summary>
        /// Public client ID property.
        /// </summary>
        private readonly string _publicClientId;



        string isldap = "false";

        /// <summary>
        /// Database Store property.
        /// </summary>
        private Oauth_APIEntities databaseManager = new Oauth_APIEntities();

        #endregion

        #region Default Constructor method.

        /// <summary>
        /// Default Constructor method.
        /// </summary>
        /// <param name="publicClientId">Public client ID parameter</param>
        public AppOAuthProvider(string publicClientId)
        {
            //TODO: Pull from configuration
            if (publicClientId == null)
            {
                throw new ArgumentNullException(nameof(publicClientId));
            }

            // Settings.
            _publicClientId = publicClientId;
        }

        #endregion

        #region Grant resource owner credentials override method.

        /// <summary>
        /// Grant resource owner credentials overload method.
        /// </summary>
        /// <param name="context">Context parameter</param>
        /// <returns>Returns when task is completed</returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // Initialization.
            string usernameVal = context.UserName;
            string passwordVal = context.Password;
            List<LoginByUsernamePassword_Result> user = null;
            if (isldap.ToLower() == "true")
            {

                var isLADAPValid = AuthenticateAndMakeAsLoginUser(usernameVal, passwordVal);
                if (isLADAPValid)
                {
                    user = this.databaseManager.LoginByUsernamePassword(usernameVal, passwordVal).ToList();
                }

            }
            else
            {
                user = this.databaseManager.LoginByUsernamePassword(usernameVal, passwordVal).ToList();
            }
            // Verification.
            if (user == null || user.Count() <= 0)
            {
                if (isldap.ToLower() == "false")
                {

                    // Settings.
                    context.SetError("invalid_grant", "The user name or password is incorrect.");

                }
                else
                {
                    context.SetError("invalid_grant", "LDAP configured and the user name or password is incorrect.");

                }
                // Retuen info.
                return;
            }

            // Initialization.
            var claims = new List<Claim>();
            var userInfo = user.FirstOrDefault();

            // Setting
            claims.Add(new Claim(ClaimTypes.Name, userInfo.username));

            // Setting Claim Identities for OAUTH 2 protocol.
            ClaimsIdentity oAuthClaimIdentity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookiesClaimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationType);

            // Setting user authentication.
            AuthenticationProperties properties = CreateProperties(userInfo.username);
            AuthenticationTicket ticket = new AuthenticationTicket(oAuthClaimIdentity, properties);

            // Grant access to authorize user.
            context.Validated(ticket);
            context.Request.Context.Authentication.SignIn(cookiesClaimIdentity);
        }

        #endregion

        #region Token endpoint override method.

        /// <summary>
        /// Token endpoint override method
        /// </summary>
        /// <param name="context">Context parameter</param>
        /// <returns>Returns when task is completed</returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                // Adding.
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion

        #region Validate Client authntication override method

        /// <summary>
        /// Validate Client authntication override method
        /// </summary>
        /// <param name="context">Contect parameter</param>
        /// <returns>Returns validation of client authentication</returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            isldap = context.Parameters.GetValues("IsLdap")[0];
            //isldap[0];
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                // Validate Authoorization.
                context.Validated();
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion

        #region Validate client redirect URI override method

        /// <summary>
        /// Validate client redirect URI override method
        /// </summary>
        /// <param name="context">Context parmeter</param>
        /// <returns>Returns validation of client redirect URI</returns>
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            // Verification.
            if (context.ClientId == _publicClientId)
            {
                // Initialization.
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                // Verification.
                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    // Validating.
                    context.Validated();
                }
            }

            // Return info.
            return Task.FromResult<object>(null);
        }

        #endregion

        #region Create Authentication properties method.

        /// <summary>
        /// Create Authentication properties method.
        /// </summary>
        /// <param name="userName">User name parameter</param>
        /// <returns>Returns authenticated properties.</returns>
        public static AuthenticationProperties CreateProperties(string userName)
        {
            // Settings.
            IDictionary<string, string> data = new Dictionary<string, string>
                                               {
                                                   { "userName", userName }
                                               };

            // Return info.
            return new AuthenticationProperties(data);
        }

        #endregion

        string _path = "LDAP://JTINDIA.COM";



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


                isValidUser = true;
            }
            catch (Exception ex)
            {
                var dex = "error in LDAP" + ex.Message;
                throw new Exception(dex);
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

        public bool AuthenticateByUsername(string Username)
        {
            PersonLogin domainPersonLogin = null;
            LDAPConfig objLDAPConfig = new LDAPConfig
            {
                IsConfigured = true,
                IsAuthByPassword = true,
                LDAPPath = "LDAP://JTINDIA.COM",
                UserName = "jt113",
                Password = "adminjt113",
                ModifiedBy = 1,
                ModifiedDate = new DateTime()
            };
            string userName = Username;
            if (!string.IsNullOrWhiteSpace(userName))
            {
                //  bool isValidLDAPUser = new LDAPAuthentication(objLDAPConfig.LDAPPath, objLDAPConfig.UserName, Encryption.DecryptText(objLDAPConfig.Password)).AuthenticateWithUserName(userName);
                bool isValidLDAPUser = new LDAPAuthentication(objLDAPConfig.LDAPPath, objLDAPConfig.UserName, objLDAPConfig.Password).AuthenticateWithUserName(userName);

                if(isValidLDAPUser)
                {
                    domainPersonLogin = new PersonLogin
                    {
                        IsLDAPUser = true,
                        Password = "",
                        UserName = ""
                    };



                }

            }

            return true;
        }

        /// <summary>
        /// data class
        /// </summary>
        public class LDAPConfig
        {
            public LDAPConfig() { }

            public bool IsConfigured { get; set; }
            public bool IsAuthByPassword { get; set; }
            public string LDAPPath { get; set; }
            public string UserName { get; set; }
            public string Password { get; set; }
            public DateTime? ModifiedDate { get; set; }
            public long ModifiedBy { get; set; }





        }
        public class PersonLogin
        {
            public PersonLogin() { }

            public string UserName { get; set; }
            public string Password { get; set; }
         
            public bool IsLDAPUser { get; set; }
        }
    }
}