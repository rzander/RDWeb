using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using Microsoft.Net.Http.Headers;
using System.Web;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace WebApplication1.Controllers
{


    [ApiController]
    [Route("[controller]")]
    public class rdwebController : Controller
    {
        [HttpGet]
        [Route("feed/webfeed.aspx")]
        public IActionResult Index()
        {
            this.Response.Headers["Cache-Control"] = "private";
            string sXML = System.IO.File.ReadAllText("Resources.xml");
            //return Content(sXML);
            return Content(sXML, "application/x-msts-radc+xml; charset=utf-8");
            //return View();
        }

        [HttpGet]
        [Route("pages/rdp/{filename}")]
        public IActionResult Resources(string filename)
        {
            //if (System.IO.Path.GetExtension(filename).ToLower() == "rdp")
            //{
            //    string sFile = System.IO.File.ReadAllText(Path.Combine("rdp", filename));
            //    return Content(sFile);
            //}

            //string filename = "File.pdf"; AppDomain.CurrentDomain.BaseDirectory,
            string filepath = System.IO.Path.Combine("rdp", filename);
            byte[] filedata = System.IO.File.ReadAllBytes(filepath);
            var provider = new FileExtensionContentTypeProvider();
            string contentType;
            if (!provider.TryGetContentType(filepath, out contentType))
            {
                contentType = "application/octet-stream";
            }

            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = System.IO.Path.GetFileName(filepath),
                Inline = false,
            };

            Response.Headers.Add("Content-Disposition", cd.ToString());

            return File(filedata, contentType);
        }


        [HttpGet]
        [HttpPost]
        [Route("feed/RDWebService.asmx")]
        public IActionResult RDWebService()
        {
            string sXML = System.IO.File.ReadAllText("RDWebService.xml");
            return Content(sXML, "text/xml");
            //return View();
        }
    }

    public class BasicAuthenticationAttribute : ActionFilterAttribute
    {
        public string BasicRealm { get; set; }
        protected string Username { get; set; }
        protected string Password { get; set; }

        public BasicAuthenticationAttribute(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            var req = filterContext.HttpContext.Request;
            var auth = req.Headers["Authorization"];
            if (!String.IsNullOrEmpty(auth))
            {
                var cred = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(auth.ToString().Substring(6))).Split(':');
                var user = new { Name = cred[0], Pass = cred[1] };
                if (user.Name == Username && user.Pass == Password) return;
            }
            var res = filterContext.HttpContext.Response;
            res.StatusCode = 401;
            res.Headers.Add("WWW-Authenticate", String.Format("Basic realm=\"{0}\"", BasicRealm ?? "Ryadel"));
            //res.End();
        }
    }
}