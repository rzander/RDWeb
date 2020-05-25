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
using System.Xml;

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
            var doc = createXML("BPA");
            doc = AppendAppResource(doc, "Notepad");
            doc = AppendAppResource(doc, "Adobe Photoshop 2020"); 
            doc = AppendDesktopResource(doc, "WIN10-RDP");
            string sXML = doc.InnerXml;
            //this.Response.Headers["Cache-Control"] = "private";
            //string sXML = System.IO.File.ReadAllText("Resources.xml");
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


        public static XmlDocument createXML(string Name = "RDWEB", string TerminalServer = "ts01.contoso.com")
        {
            XmlDocument doc = new XmlDocument();
            XmlDeclaration xmlDeclaration = doc.CreateXmlDeclaration("1.0", "utf-8", null);
            XmlElement root = doc.DocumentElement;
            doc.InsertBefore(xmlDeclaration, root);

            XmlElement eResourceCollection = doc.CreateElement(string.Empty, "ResourceCollection", string.Empty);
            eResourceCollection.SetAttribute("PubDate", DateTime.UtcNow.ToString("s") + "Z");
            eResourceCollection.SetAttribute("SchemaVersion", "2.1");
            eResourceCollection.SetAttribute("xmlns", "http://schemas.microsoft.com/ts/2007/05/tswf");

            XmlElement ePublisher = doc.CreateElement(string.Empty, "Publisher", string.Empty);
            ePublisher.SetAttribute("LastUpdated", DateTime.UtcNow.ToString("s") + "Z");
            ePublisher.SetAttribute("Name", Name);
            ePublisher.SetAttribute("ID", "rzander.azurewebsites.net");
            ePublisher.SetAttribute("Description", "RDP Resources");
            ePublisher.SetAttribute("SupportsReconnect", "true");

            XmlElement eResources = doc.CreateElement(string.Empty, "Resources", string.Empty);
            XmlElement eTerminalServers = doc.CreateElement(string.Empty, "TerminalServers", string.Empty);
            XmlElement eTerminalServer = doc.CreateElement(string.Empty, "TerminalServer", string.Empty);
            eTerminalServer.SetAttribute("ID", TerminalServer);
            eTerminalServer.SetAttribute("Name", TerminalServer);
            eTerminalServer.SetAttribute("LastUpdated", DateTime.UtcNow.ToString("s") + "Z");

            eTerminalServers.AppendChild(eTerminalServer);
            ePublisher.AppendChild(eResources);
            ePublisher.AppendChild(eTerminalServers);
            eResourceCollection.AppendChild(ePublisher);
            doc.AppendChild(eResourceCollection);

            return doc;
        }

        public static XmlDocument AppendAppResource(XmlDocument doc, string App)
        {
            XmlElement eResource = doc.CreateElement(string.Empty, "Resource", string.Empty);
            eResource.SetAttribute("ID", DateTime.Now.Ticks.ToString());
            eResource.SetAttribute("Alias", App);
            eResource.SetAttribute("Title", App);
            eResource.SetAttribute("LastUpdated", DateTime.UtcNow.ToString("s") + "Z");
            eResource.SetAttribute("Type", "RemoteApp");
            eResource.SetAttribute("ShowByDefault", "true");

            XmlElement eIcons = doc.CreateElement(string.Empty, "Icons", string.Empty);
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", App + ".ico")))
            {
                XmlElement eIconRaw = doc.CreateElement(string.Empty, "IconRaw", string.Empty);
                eIconRaw.SetAttribute("FileType", "Ico");
                eIconRaw.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ App.ToLower() }.ico");
                eIcons.AppendChild(eIconRaw);
            }
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", App + "32.png")))
            {
                XmlElement eIcon32 = doc.CreateElement(string.Empty, "Icon32", string.Empty);
                eIcon32.SetAttribute("Dimensions", "32x32");
                eIcon32.SetAttribute("FileType", "Png");
                eIcon32.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ App.ToLower() }32.png");
                eIcons.AppendChild(eIcon32);
            }
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", App + "64.png")))
            {
                XmlElement eIcon64 = doc.CreateElement(string.Empty, "Icon64", string.Empty);
                eIcon64.SetAttribute("Dimensions", "64x64");
                eIcon64.SetAttribute("FileType", "Png");
                eIcon64.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ App.ToLower() }64.png");
                eIcons.AppendChild(eIcon64);
            }

            XmlElement eFileExtensions = doc.CreateElement(string.Empty, "FileExtensions", string.Empty);
            XmlElement eFolders = doc.CreateElement(string.Empty, "Folders", string.Empty);
            XmlElement eFolder = doc.CreateElement(string.Empty, "Folder", string.Empty);
            eFolder.SetAttribute("Name", "/");
            eFolders.AppendChild(eFolder);

            XmlElement eHostingTerminalServers = doc.CreateElement(string.Empty, "HostingTerminalServers", string.Empty);
            XmlElement eHostingTerminalServer = doc.CreateElement(string.Empty, "HostingTerminalServer", string.Empty);
            XmlElement eResourceFile = doc.CreateElement(string.Empty, "ResourceFile", string.Empty);
            eResourceFile.SetAttribute("FileExtension", ".rdp");
            eResourceFile.SetAttribute("URL", $"/rdweb/pages/rdp/{ App.ToLower() }.rdp");
            XmlElement eTerminalServerRef = doc.CreateElement(string.Empty, "TerminalServerRef", string.Empty);
            eTerminalServerRef.SetAttribute("Ref", doc.SelectSingleNode("//TerminalServers/TerminalServer").Attributes["ID"].Value);

            eHostingTerminalServer.AppendChild(eResourceFile);
            eHostingTerminalServer.AppendChild(eTerminalServerRef);
            eHostingTerminalServers.AppendChild(eHostingTerminalServer);

            eResource.AppendChild(eIcons);
            eResource.AppendChild(eFileExtensions);
            eResource.AppendChild(eFolders);
            eResource.AppendChild(eHostingTerminalServers);
            doc.SelectSingleNode("//Resources").AppendChild(eResource);

            return doc;
        }

        public static XmlDocument AppendDesktopResource(XmlDocument doc, string Host)
        {
            XmlElement eResource = doc.CreateElement(string.Empty, "Resource", string.Empty);
            eResource.SetAttribute("ID", DateTime.Now.Ticks.ToString());
            eResource.SetAttribute("Alias", Host);
            eResource.SetAttribute("Title", Host);
            eResource.SetAttribute("LastUpdated", DateTime.UtcNow.ToString("s") + "Z");
            eResource.SetAttribute("Type", "Desktop");
            //eResource.SetAttribute("ShowByDefault", "true");

            XmlElement eIcons = doc.CreateElement(string.Empty, "Icons", string.Empty);
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", Host + ".ico")))
            {
                XmlElement eIconRaw = doc.CreateElement(string.Empty, "IconRaw", string.Empty);
                eIconRaw.SetAttribute("FileType", "Ico");
                eIconRaw.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ Host.ToLower() }.ico");
                eIcons.AppendChild(eIconRaw);
            }
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", Host + "32.png")))
            {
                XmlElement eIcon32 = doc.CreateElement(string.Empty, "Icon32", string.Empty);
                eIcon32.SetAttribute("Dimensions", "32x32");
                eIcon32.SetAttribute("FileType", "Png");
                eIcon32.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ Host.ToLower() }32.png");
                eIcons.AppendChild(eIcon32);
            }
            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", Host + "64.png")))
            {
                XmlElement eIcon64 = doc.CreateElement(string.Empty, "Icon64", string.Empty);
                eIcon64.SetAttribute("Dimensions", "64x64");
                eIcon64.SetAttribute("FileType", "Png");
                eIcon64.SetAttribute("FileURL", $"/rdweb/pages/rdp/{ Host.ToLower() }64.png");
                eIcons.AppendChild(eIcon64);
            }

            XmlElement eFileExtensions = doc.CreateElement(string.Empty, "FileExtensions", string.Empty);
            //XmlElement eFolders = doc.CreateElement(string.Empty, "Folders", string.Empty);
            //XmlElement eFolder = doc.CreateElement(string.Empty, "Folder", string.Empty);
            //eFolder.SetAttribute("Name", "/");
            //eFolders.AppendChild(eFolder);

            XmlElement eHostingTerminalServers = doc.CreateElement(string.Empty, "HostingTerminalServers", string.Empty);
            XmlElement eHostingTerminalServer = doc.CreateElement(string.Empty, "HostingTerminalServer", string.Empty);
            XmlElement eResourceFile = doc.CreateElement(string.Empty, "ResourceFile", string.Empty);
            eResourceFile.SetAttribute("FileExtension", ".rdp");
            eResourceFile.SetAttribute("URL", $"/rdweb/pages/rdp/{ Host.ToLower() }.rdp");
            XmlElement eTerminalServerRef = doc.CreateElement(string.Empty, "TerminalServerRef", string.Empty);
            eTerminalServerRef.SetAttribute("Ref", doc.SelectSingleNode("//TerminalServers/TerminalServer").Attributes["ID"].Value);

            eHostingTerminalServer.AppendChild(eResourceFile);
            eHostingTerminalServer.AppendChild(eTerminalServerRef);
            eHostingTerminalServers.AppendChild(eHostingTerminalServer);

            eResource.AppendChild(eIcons);
            eResource.AppendChild(eFileExtensions);
            //eResource.AppendChild(eFolders);
            eResource.AppendChild(eHostingTerminalServers);
            doc.SelectSingleNode("//Resources").AppendChild(eResource);

            return doc;
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