using CustomAuthenticationMVC.CustomAuthentication;
using System.Web.Mvc;

namespace CustomAuthenticationMVC.Controllers
{
    [CustomAuthorize(Roles = "User")]
    public class UserController : Controller
    {
        // GET: User
        public ActionResult Index()
        {
            return View();
        }
    }
}