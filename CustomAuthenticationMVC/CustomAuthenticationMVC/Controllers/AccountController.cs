using CustomAuthenticationMVC.CustomAuthentication;
using CustomAuthenticationMVC.DataAccess;
using CustomAuthenticationMVC.Models;
using Newtonsoft.Json;
using System;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Configuration;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace CustomAuthenticationMVC.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Login(string ReturnUrl = "")
        {
            if (User.Identity.IsAuthenticated)
            {
                return LogOut();
            }
            ViewBag.ReturnUrl = ReturnUrl;
            return View();
        }

        [HttpPost]
        public ActionResult Login(LoginView loginView, string ReturnUrl = "")
        {
            if (ModelState.IsValid)
            {
                if (Membership.ValidateUser(loginView.UserName, loginView.Password))
                {
                    var user = (CustomMembershipUser)Membership.GetUser(loginView.UserName, false);
                    if (user != null)
                    {
                        CustomSerializeModel userModel = new Models.CustomSerializeModel()
                        {
                            UserId = user.UserId,
                            FirstName = user.FirstName,
                            LastName = user.LastName,
                            RoleName = user.Roles.Select(r => r.RoleName).ToList()
                        };

                        string userData = JsonConvert.SerializeObject(userModel);
                        FormsAuthenticationTicket authTicket = new FormsAuthenticationTicket
                            (
                            1, loginView.UserName, DateTime.Now, DateTime.Now.AddMinutes(15), false, userData
                            );

                        string enTicket = FormsAuthentication.Encrypt(authTicket);
                        HttpCookie faCookie = new HttpCookie("Cookie1", enTicket);
                        Response.Cookies.Add(faCookie);
                    }

                    if (Url.IsLocalUrl(ReturnUrl))
                    {
                        return Redirect(ReturnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index");
                    }
                }
            }
            ModelState.AddModelError("", "Something Wrong : Username or Password invalid ^_^ ");
            return View(loginView);
        }

        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registration(RegistrationView registrationView)
        {
            var statusRegistration = false;
            var messageRegistration = string.Empty;
            var activationCode = Guid.Empty;

            if (ModelState.IsValid)
            {
                // Email Verification
                var userName = Membership.GetUserNameByEmail(registrationView.Email);
                if (!string.IsNullOrEmpty(userName))
                {
                    ModelState.AddModelError("Warning Email", "Sorry: Email already Exists");
                    return View(registrationView);
                }

                //Save User Data
                using (AuthenticationDB dbContext = new AuthenticationDB())
                {
                    var user = new User()
                    {
                        Username = registrationView.Username,
                        FirstName = registrationView.FirstName,
                        LastName = registrationView.LastName,
                        Email = registrationView.Email,
                        Password = registrationView.Password,
                        ActivationCode = Guid.NewGuid(),
                    };

                    dbContext.Users.Add(user);
                    dbContext.SaveChanges();
                    activationCode = user.ActivationCode;
                }

                //Verification Email
                VerificationEmail(registrationView.Email, Convert.ToString(activationCode));
                messageRegistration = "Your account has been created successfully. ^_^";
                statusRegistration = true;
            }
            else
            {
                messageRegistration = "Something Wrong!";
            }
            ViewBag.Message = messageRegistration;
            ViewBag.Status = statusRegistration;

            return View(registrationView);
        }

        public static void SendMail(string to, string subject, string body)
        {
            var mailSettings = (SmtpSection)ConfigurationManager.GetSection("system.net/mailSettings/smtp");
            if (mailSettings != null)
            {
                var port = mailSettings.Network.Port;
                var from = mailSettings.Network.UserName;
                var host = mailSettings.Network.Host;
                var pwd = mailSettings.Network.Password;
                var uid = mailSettings.Network.UserName;

                var message = new MailMessage
                {
                    From = new MailAddress(from)
                };
                message.To.Add(new MailAddress(to));
                message.CC.Add(new MailAddress(from));
                message.Subject = subject;
                message.IsBodyHtml = true;
                message.Body = body;

                using (var client = new SmtpClient
                {
                    Host = host,
                    Port = port,
                    Credentials = new NetworkCredential(uid, pwd),
                    EnableSsl = true
                })
                {
                    try
                    {
                        client.Send(message);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Mail not sent due to " + Convert.ToString(ex.Message));
                    }
                }
            }
        }

        [HttpGet]
        public ActionResult ActivationAccount(string id)
        {
            var statusAccount = false;
            using (AuthenticationDB dbContext = new DataAccess.AuthenticationDB())
            {
                var userAccount = dbContext.Users.FirstOrDefault(u => u.ActivationCode.ToString().Equals(id));

                if (userAccount != null)
                {
                    userAccount.IsActive = true;
                    dbContext.SaveChanges();
                    statusAccount = true;
                }
                else
                {
                    ViewBag.Message = "Something Wrong !!";
                }
            }
            ViewBag.Status = statusAccount;
            return View();
        }

        public ActionResult LogOut()
        {
            var cookie = new HttpCookie("Cookie1", "")
            {
                Expires = DateTime.Now.AddYears(-1)
            };
            Response.Cookies.Add(cookie);

            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "Account", null);
        }

        [NonAction]
        public void VerificationEmail(string email, string activationCode)
        {
            var url = string.Format("/Account/ActivationAccount/{0}", activationCode);
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, url);
            var subject = "Activation Account !";
            var body = "<br/> Please click on the following link in order to activate your account" + "<br/><a href='" + link + "'> Activation Account ! </a>";
            body += @"<br/>CONFIDENTIALITY NOTICE:<br/>The contents of this email message and any attachments are intended solely for the addressee(s)
                        and may contain confidential and/or privileged information and may be legally protected from
                        disclosure. If you are not the intended recipient of this message or their agent, or if this message
                        has been addressed to you in error, please immediately alert the sender by reply email and then
                        delete this message and any attachments. If you are not the intended recipient, you are hereby
                        notified that any use, dissemination, copying, or storage of this message or its attachments is
                        strictly prohibited.                         ";
            SendMail(email, subject, body);
        }
    }
}