using System;
using System.Linq;
using System.Threading.Tasks;
using SQLMembership_Identity_OWIN;
using Microsoft.AspNet.Identity;

namespace SQLMembership_Identity_OWIN.IdentityAcccount
{
    public partial class Register : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            
        }

        protected void Submit_Click(object sender, EventArgs e)
        {
            var currentApplicationId = new ApplicationDbContext().Applications.SingleOrDefault(x => x.ApplicationName == "/").ApplicationId;

            var manager = new UserManager();
            User user = new User() { UserName = Username.Text,ApplicationId=currentApplicationId, LoweredUserName=Username.Text.ToLower()};

          //  user.CreatePasswordLogin();
            user.IsApproved = true;

            // Copy the PasswordSalt and Passwrod format

            var result = manager.Create(user, Password.Text);

            if (result.Succeeded)
            {
                IdentityHelper.SignIn(manager, user, isPersistent: false);
                IdentityHelper.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
            }
            else
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault());
            }
        }

    }
}