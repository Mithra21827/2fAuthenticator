using _2FAuthentication.Models;
using Google.Authenticator;
using MessagePack.Formatters;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text;


namespace _2FAuthentication.Controllers
{
    public class HomeController : Controller
    {

        private const string key = "qa123!@#";
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Login() {

            return View();
        }

        [HttpPost]

        public IActionResult Login(Login login) {
            string message = "";
            bool status = false;

            if (login.Username == "Admin" && login.Password == "Password1")
            {
                message = "2fa verification";
                status = true;
                HttpContext.Session.SetString("Username", login.Username);

                TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
                string UserUniqueKey = login.Username + key;
                HttpContext.Session.SetString("UserUniqueKey", UserUniqueKey);
                var setupInfo = tfa.GenerateSetupCode("Dotnet", login.Username, ConvertSecretToBytes(UserUniqueKey, false), 300);
                ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                //ViewBag.SetupCode = setupInfo.ManualEntryKey;
            }
            else {
                message = "Invalid credentials";
            }
            ViewBag.Message = message;
            ViewBag.Status = status;    

            return View();
        }

        private static byte[] ConvertSecretToBytes(string secret, bool secretIsBase32)=>
            secretIsBase32 ? Base32Encoding.ToBytes(secret) : Encoding.UTF8.GetBytes(secret);

        public IActionResult MyProfile() {
            string username = HttpContext.Session.GetString("Username").ToString();
            string isvalid2fa = HttpContext.Session.GetString("IsValid2FA");
            
            if (username == null || isvalid2fa == null || !Convert.ToBoolean(isvalid2fa)) {
                return RedirectToAction("Login");
            }
            return View();
        }

        public IActionResult Verify2FA() {
            var token = Request.Form["passcode"];
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            string UserUniqueKey = HttpContext.Session.GetString("UserUniqueKey");
            bool isValid = tfa.ValidateTwoFactorPIN(UserUniqueKey,token);
            if (isValid)
            {
                HttpContext.Session.SetString("IsValid2FA", "true");
                return RedirectToAction("Index", "Home");
            }
            return RedirectToAction("Login", "Home");
        }
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}