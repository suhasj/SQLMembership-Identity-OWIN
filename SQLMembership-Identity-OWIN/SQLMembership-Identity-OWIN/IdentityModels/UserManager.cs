using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace SQLMembership_Identity_OWIN
{
    public class UserManager : UserManager<User>
    {
        public UserManager()
            : base(new UserStore<User>(new ApplicationDbContext()))
        {
            this.PasswordHasher = new SQLPasswordHasher();
        }
    }


    public class SQLPasswordHasher : PasswordHasher
    {
        public override string HashPassword(string password)
        {
            return base.HashPassword(password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            string[] passwordProperties = hashedPassword.Split('|');
            if (passwordProperties.Length != 3)
            {
                return base.VerifyHashedPassword(hashedPassword, providedPassword);
            }
            else
            {
                string passwordHash = passwordProperties[0];
                int passwordformat = 1;
                string salt = passwordProperties[2];
                if (String.Equals(EncodePassword(providedPassword, passwordformat, salt), passwordHash, StringComparison.CurrentCultureIgnoreCase))
                {
                    return PasswordVerificationResult.Success;
                }
                else
                {
                    return PasswordVerificationResult.Failed;
                }
            }
        }

        private string EncodePassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0)
            {
                return pass;
            }
            byte[] bytes = Encoding.Unicode.GetBytes(pass);
            byte[] array = Convert.FromBase64String(salt);
            byte[] inArray = null;
            if (passwordFormat == 1)
            {
                HashAlgorithm hashAlgorithm = HashAlgorithm.Create("SHA1");

                if (hashAlgorithm is KeyedHashAlgorithm)
                {
                    KeyedHashAlgorithm keyedHashAlgorithm = (KeyedHashAlgorithm)hashAlgorithm;
                    if (keyedHashAlgorithm.Key.Length == array.Length)
                    {
                        keyedHashAlgorithm.Key = array;
                    }
                    else
                    {
                        if (keyedHashAlgorithm.Key.Length < array.Length)
                        {
                            byte[] array2 = new byte[keyedHashAlgorithm.Key.Length];
                            Buffer.BlockCopy(array, 0, array2, 0, array2.Length);
                            keyedHashAlgorithm.Key = array2;
                        }
                        else
                        {
                            byte[] array3 = new byte[keyedHashAlgorithm.Key.Length];
                            int num;
                            for (int i = 0; i < array3.Length; i += num)
                            {
                                num = Math.Min(array.Length, array3.Length - i);
                                Buffer.BlockCopy(array, 0, array3, i, num);
                            }
                            keyedHashAlgorithm.Key = array3;
                        }
                    }
                    inArray = keyedHashAlgorithm.ComputeHash(bytes);
                }
                else
                {
                    byte[] array4 = new byte[array.Length + bytes.Length];
                    Buffer.BlockCopy(array, 0, array4, 0, array.Length);
                    Buffer.BlockCopy(bytes, 0, array4, array.Length, bytes.Length);
                    inArray = hashAlgorithm.ComputeHash(array4);
                }
            }
            return Convert.ToBase64String(inArray);
        }

    }

    public static class IdentityHelper
    {
        // Used for XSRF when linking external logins
        public const string XsrfKey = "XsrfId";

        public static void SignIn(UserManager manager, User user, bool isPersistent)
        {
            IAuthenticationManager authenticationManager = HttpContext.Current.GetOwinContext().Authentication;
            authenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = manager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }

        public const string ProviderNameKey = "providerName";
        public static string GetProviderNameFromRequest(HttpRequest request)
        {
            return request[ProviderNameKey];
        }

        public static string GetExternalLoginRedirectUrl(string accountProvider)
        {
            return "/IdentityAccount/RegisterExternalLogin.aspx?" + ProviderNameKey + "=" + accountProvider;
        }

        private static bool IsLocalUrl(string url)
        {
            return !string.IsNullOrEmpty(url) && ((url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))) || (url.Length > 1 && url[0] == '~' && url[1] == '/'));
        }

        public static void RedirectToReturnUrl(string returnUrl, HttpResponse response)
        {
            if (!String.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl))
            {
                response.Redirect(returnUrl);
            }
            else
            {
                response.Redirect("~/");
            }
        }
    }
}