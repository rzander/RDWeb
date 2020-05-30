using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Xml;
using System.IO;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.Advanced;
using SixLabors.ImageSharp.Formats.Png;

namespace WebApplication1.Controllers
{


    public class BasicAuthenticationAttribute : ActionFilterAttribute
    {
        public BasicAuthenticationAttribute(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

        public string BasicRealm { get; set; }
        protected string Password { get; set; }
        protected string Username { get; set; }
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

    [ApiController]
    [Route("[controller]")]
    public class rdwebController : Controller
    {
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

            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + ".ico")))
            {
                XmlElement eIconRaw = doc.CreateElement(string.Empty, "IconRaw", string.Empty);
                eIconRaw.SetAttribute("FileType", "Ico");
                eIconRaw.SetAttribute("FileURL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }.ico");
                eIcons.AppendChild(eIconRaw);
            }

            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + ".png")))
            {
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + "16.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "apps", App + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(16, 16) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "apps", App + "16.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + "32.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "apps", App + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(32, 32) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "apps", App + "32.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + "64.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "apps", App + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(64, 64) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "apps", App + "64.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "apps", App + "128.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "apps", App + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(128, 128) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "apps", App + "128.png"), imageEncoder);
                        }
                    }
                }

                XmlElement eIcon16 = doc.CreateElement(string.Empty, "Icon16", string.Empty);
                eIcon16.SetAttribute("Dimensions", "16x16");
                eIcon16.SetAttribute("FileType", "Png");
                eIcon16.SetAttribute("FileURL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }16.png");
                eIcons.AppendChild(eIcon16);

                XmlElement eIcon32 = doc.CreateElement(string.Empty, "Icon32", string.Empty);
                eIcon32.SetAttribute("Dimensions", "32x32");
                eIcon32.SetAttribute("FileType", "Png");
                eIcon32.SetAttribute("FileURL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }32.png");
                eIcons.AppendChild(eIcon32);

                XmlElement eIcon64 = doc.CreateElement(string.Empty, "Icon64", string.Empty);
                eIcon64.SetAttribute("Dimensions", "64x64");
                eIcon64.SetAttribute("FileType", "Png");
                eIcon64.SetAttribute("FileURL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }64.png");
                eIcons.AppendChild(eIcon64);

                //XmlElement eIcon128 = doc.CreateElement(string.Empty, "Icon128", string.Empty);
                //eIcon128.SetAttribute("Dimensions", "128x128");
                //eIcon128.SetAttribute("FileType", "Png");
                //eIcon128.SetAttribute("FileURL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }128.png");
                //eIcons.AppendChild(eIcon128);
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
            eResourceFile.SetAttribute("URL", $"/rdweb/pages/rdp/apps/{ App.ToLower() }.rdp");
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

            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + ".ico")))
            {
                XmlElement eIconRaw = doc.CreateElement(string.Empty, "IconRaw", string.Empty);
                eIconRaw.SetAttribute("FileType", "Ico");
                eIconRaw.SetAttribute("FileURL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }.ico");
                eIcons.AppendChild(eIconRaw);
            }

            if (System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + ".png")))
            {
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + "16.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "desktop", Host + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(16, 16) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "desktop", Host + "16.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + "32.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "desktop", Host + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(32, 32) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "desktop", Host + "32.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + "64.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "desktop", Host + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(64, 64) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "desktop", Host + "64.png"), imageEncoder);
                        }
                    }
                }
                if (!System.IO.File.Exists(System.IO.Path.Combine("rdp", "desktop", Host + "128.png")))
                {
                    using (Image image = Image.Load(System.IO.Path.Combine("rdp", "desktop", Host + ".png")))
                    {
                        image.Mutate(i => i.Resize(new ResizeOptions { Size = new Size(128, 128) }));
                        using (var imgs = new MemoryStream())
                        {
                            var imageEncoder = image.GetConfiguration().ImageFormatsManager.FindEncoder(PngFormat.Instance);
                            image.Save(Path.Combine("rdp", "desktop", Host + "128.png"), imageEncoder);
                        }
                    }
                }

                XmlElement eIcon16 = doc.CreateElement(string.Empty, "Icon16", string.Empty);
                eIcon16.SetAttribute("Dimensions", "16x16");
                eIcon16.SetAttribute("FileType", "Png");
                eIcon16.SetAttribute("FileURL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }32.png");
                eIcons.AppendChild(eIcon16);

                XmlElement eIcon32 = doc.CreateElement(string.Empty, "Icon32", string.Empty);
                eIcon32.SetAttribute("Dimensions", "32x32");
                eIcon32.SetAttribute("FileType", "Png");
                eIcon32.SetAttribute("FileURL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }32.png");
                eIcons.AppendChild(eIcon32);

                XmlElement eIcon64 = doc.CreateElement(string.Empty, "Icon64", string.Empty);
                eIcon64.SetAttribute("Dimensions", "64x64");
                eIcon64.SetAttribute("FileType", "Png");
                eIcon64.SetAttribute("FileURL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }64.png");
                eIcons.AppendChild(eIcon64);

                //XmlElement eIcon128 = doc.CreateElement(string.Empty, "Icon128", string.Empty);
                //eIcon128.SetAttribute("Dimensions", "128x128");
                //eIcon128.SetAttribute("FileType", "Png");
                //eIcon128.SetAttribute("FileURL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }128.png");
                //eIcons.AppendChild(eIcon128);
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
            eResourceFile.SetAttribute("URL", $"/rdweb/pages/rdp/desktop/{ Host.ToLower() }.rdp");
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

        [HttpGet]
        [Route("feed/webfeed.aspx")]
        public IActionResult Index()
        {
            var doc = createXML("BPA");
            if (!Directory.Exists(Path.Combine("rdp", "apps")))
                Directory.CreateDirectory(Path.Combine("rdp", "apps"));
            foreach (string sFile in Directory.GetFiles(Path.Combine("rdp", "apps"), "*.rdp", SearchOption.AllDirectories))
            {
                if (Path.GetFileName(sFile).ToLower().StartsWith("win10-"))
                {
                    Console.WriteLine("Adding Desktop " + Path.GetFileName(sFile).Split('.')[0]);
                    doc = AppendDesktopResource(doc, Path.GetFileName(sFile).Split('.')[0]);
                }else
                {
                    Console.WriteLine("Adding App " + Path.GetFileName(sFile).Split('.')[0]);
                    doc = AppendAppResource(doc, Path.GetFileName(sFile).Split('.')[0]);
                }

            }

            if (!Directory.Exists(Path.Combine("rdp", "desktop")))
                Directory.CreateDirectory(Path.Combine("rdp", "desktop"));
            foreach (string sFile in Directory.GetFiles(Path.Combine("rdp", "desktop"), "*.rdp", SearchOption.AllDirectories))
            {
                Console.WriteLine("Adding Desktop " + Path.GetFileName(sFile).Split('.')[0]);
                doc = AppendDesktopResource(doc, Path.GetFileName(sFile).Split('.')[0]);
            }

            string sXML = doc.InnerXml;

            return Content(sXML, "application/x-msts-radc+xml; charset=utf-8");
            //return View();
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

        [HttpGet]
        [Route("pages/rdp/{rtype}/{filename}")]
        public IActionResult Resources(string rtype,string filename)
        {
            //if (System.IO.Path.GetExtension(filename).ToLower() == "rdp")
            //{
            //    string sFile = System.IO.File.ReadAllText(Path.Combine("rdp", filename));
            //    return Content(sFile);
            //}

            //string filename = "File.pdf"; AppDomain.CurrentDomain.BaseDirectory,
            string filepath = System.IO.Path.Combine("rdp", rtype,  filename);
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
    }
}