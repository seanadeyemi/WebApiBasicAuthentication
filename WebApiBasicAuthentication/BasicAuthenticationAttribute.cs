using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using WebApiBasicAuthentication.Models;

namespace WebApiBasicAuthentication
{
    public class BasicAuthenticationAttribute : AuthorizationFilterAttribute
    {

      
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if(actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
            else
            {

                
                string authenticationToken = actionContext.Request.Headers.Authorization.Parameter;
                string decodedauthentionString = Encoding.UTF8.GetString(Convert.FromBase64String(authenticationToken));
                string[] UserNamePassword = decodedauthentionString.Split(':');
                string userName = UserNamePassword[0];
                string password = UserNamePassword[1];

                var userManager = Startup.UserManagerFactory.Invoke();//HttpContext.Current.GetOwinContext().GetUserManager<UserManager<ApplicationUser>>();
                var user = userManager.Find(userName, password);

                if(user != null)
                {
                    Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity(userName), null);
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                }
            }
        }
    }
}