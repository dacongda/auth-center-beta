using AuthCenter.Data;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using AuthCenter.ViewModels.Response;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using NuGet.Protocol;
using SixLabors.ImageSharp.Formats.Webp;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

namespace AuthCenter.Controllers
{
    [Route("[controller]")]
    public class CasController(AuthCenterDbContext authCenterDbContext, IDistributedCache cache, IConfiguration configuration) : Controller
    {
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;

        private string RequestUrl => ControllerUtils.GetFrontUrl(_configuration, Request);

        [HttpGet("{groupName}/{clientId}/validate", Name = "CAS validate")]
        public string CasValidate(string groupName, string clientId)
        {
            var ticket = Request.Query["ticket"];
            var service = Request.Query["service"];

            if (String.IsNullOrEmpty(ticket) || String.IsNullOrEmpty(service))
            {
                return "no\n";
            }

            var storeValJson = _cache.GetString($"Login:CAS:ST:{ticket!}");
            if (String.IsNullOrEmpty(storeValJson)) { return "no\n"; }

            _cache.Remove($"Login:CAS:ST:{ticket!}");

            var storeVal = JsonSerializer.Deserialize<CasSTStore>(storeValJson);

            if (storeVal == null) { return "no\n"; }

            if (storeVal.Service != service)
            {
                return "no\n";
            }

            return $"yes\n{storeVal.CasToken.AuthenticationSuccess?.User}\n";
        }

        [HttpGet("{groupName}/{clientId}/serviceValidate", Name = "CAS Service validate")]
        [HttpGet("{groupName}/{clientId}/proxyValidate", Name = "CAS Proxy validate")]
        [HttpGet("{groupName}/{clientId}/p3/serviceValidate", Name = "CAS P3 Service validate")]
        [HttpGet("{groupName}/{clientId}/p3/proxyValidate", Name = "CAS P3 Proxy validate")]
        public async Task<IActionResult> CasServiceValidate(string groupName, string clientId)
        {
            var ticket = Request.Query["ticket"];
            var format = Request.Query["format"];
            if (String.IsNullOrEmpty(format))
            {
                format = "xml";
            }

            if (!ticket.ToString().StartsWith("ST"))
            {
                return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format!);
            }

            var service = Request.Query["service"];
            var pgtUrl = Request.Query["pgtUrl"];

            var storeValJson = await _cache.GetStringAsync($"Login:CAS:ST:{ticket}");
            if (String.IsNullOrEmpty(storeValJson))
            {
                return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format!);
            }

            _cache.Remove($"Login:CAS:ST:{ticket}");

            var storeVal = JsonSerializer.Deserialize<CasSTStore>(storeValJson);

            if (storeVal == null) { return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format!); }

            if (storeVal.Service != service)
            {
                return CasResult.GetFailResponse("INVALID_SERVICE", "Service does not match", format!);
            }

            var application = _authCenterDbContext.Application.Where(app => app.ClientId == clientId)
                .Include(app => app.Cert).FirstOrDefault();
            if (application is null)
            {
                return Json(JSONResult.ResponseError("Application not found"));
            }

            if (!String.IsNullOrEmpty(pgtUrl))
            {
                var pgt = $"PGT-{Guid.NewGuid()}";

                var pgtStoreVal = new CasSTStore(pgt, service.ToString(), storeVal.CasToken);
                _cache.SetString($"Login:CAS:PGT:{pgt}", pgt.ToJson(), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(application.AccessExpiredSecond)
                });

                var pgtiou = storeVal.CasToken.AuthenticationSuccess!.ProxyGrantingTicket;
                var pgtUrlParsed = new UriBuilder(pgtUrl!);

                if (pgtUrlParsed.Scheme != "https")
                {
                    return CasResult.GetFailResponse("INVALID_PROXY_CALLBACK", "Callback not https", format!);
                }

                var query = HttpUtility.ParseQueryString(pgtUrlParsed.Query);
                query.Add("pgt", pgt);
                query.Add("pgtIou", pgtiou);

                pgtUrlParsed.Query = query.ToString();

                using var httpClient = new HttpClient();

                var request = new HttpRequestMessage(HttpMethod.Get, pgtUrlParsed.ToString());

                try
                {
                    var response = await httpClient.SendAsync(request);
                    if (!response.IsSuccessStatusCode)
                    {
                        return CasResult.GetFailResponse("INVALID_PROXY_CALLBACK", "Fail to send", format!);
                    }
                }
                catch (Exception e)
                {
                    return CasResult.GetFailResponse("INVALID_PROXY_CALLBACK", e.Message, format!);
                }
            }

            return CasResult.GetResponse(storeVal.CasToken, format!);
        }

        [HttpGet("{groupName}/{clientId}/proxy", Name = "CAS proxy")]
        public async Task<IActionResult> CasProxy(string groupName, string clientId)
        {
            var pgt = Request.Query["pgt"];
            var format = Request.Query["format"];
            var targetService = Request.Query["targetService"];
            
            if (String.IsNullOrEmpty(pgt) || String.IsNullOrEmpty(targetService))
            {
                CasResult.GetFailResponse("INVALID_REQUEST", "PGT and target must exist", format);
            }

            var pgtTokenJson = await _cache.GetStringAsync($"Login:CAS:PGT:{pgt}");
            if (String.IsNullOrEmpty(pgtTokenJson))
            {
                return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format);
            }

            _cache.Remove($"Login:CAS:PGT:{pgt}");

            var storeVal = JsonSerializer.Deserialize<CasSTStore>(pgtTokenJson);
            if (storeVal is null)
            {
                return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format);
            }

            if (storeVal.CasToken.AuthenticationSuccess is null)
            {
                return CasResult.GetFailResponse("INVALID_TICKET", "Ticket not recognized", format);
            }

            var application = _authCenterDbContext.Application.Where(app => app.ClientId == clientId)
                .Include(app => app.Cert).FirstOrDefault();
            if (application is null)
            {
                return Json(JSONResult.ResponseError("Application not found"));
            }

            if (storeVal.CasToken.AuthenticationSuccess.Proxies is null) storeVal.CasToken.AuthenticationSuccess.Proxies = [];
            storeVal.CasToken.AuthenticationSuccess.Proxies.Add(targetService!);

            var newTicket = $"PT-{Guid.NewGuid().ToString()}";
            var newStoreVal = new CasSTStore(newTicket, targetService!, storeVal.CasToken);
            var newStoreValJson = JsonSerializer.Serialize(newStoreVal);
            await _cache.SetStringAsync(newTicket, newStoreValJson, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(application.AccessExpiredSecond)
            });

            var sResp = new ServiceResponse
            {
                ProxySuccess = new ServiceResponse.CasProxySuccess
                {
                    ProxyTicket = newTicket,
                }
            };

            return CasResult.GetResponse(sResp, format);
        }

        [HttpPost("{groupName}/{clientId}/samlValidate", Name = "CAS saml validate")]
        public async Task<IActionResult> SamlValidate(string groupName, string clientId, string TARGET)
        {
            var rawRequest = Request.BodyReader.ToString();
            if (rawRequest is null)
            {
                return Json(JSONResult.ResponseError("Request should not be null"));
            }

            var envelopReq = CasSamlValidateRequest.FromXml(rawRequest);
            var ticket = envelopReq?.Body.CasSamlRequest.AssertionArtiface;
            if (String.IsNullOrEmpty(ticket))
            {
                return Json(JSONResult.ResponseError("Request error, AssertionArtifact not found or deseralizeError"));
            }

            var storedTokenJson = _cache.GetString($"Login:CAS:ST:{ticket}");
            if (String.IsNullOrEmpty(storedTokenJson))
            {
                return Json(JSONResult.ResponseError("Ticket not recognized"));
            }

            var storedToken = JsonSerializer.Deserialize<CasSTStore>(storedTokenJson);
            var userId = storedToken?.CasToken.AuthenticationSuccess?.User;
            if (String.IsNullOrEmpty(userId)) {
                return Json(JSONResult.ResponseError("The CAS token for ticket is not found"));
            }

            var user = await _authCenterDbContext.User
                .Where(u => u.Id == userId).Include(u => u.Group).FirstOrDefaultAsync();
            if (user == null) {
                return Json(JSONResult.ResponseError("User not found"));
            }

            var group = _authCenterDbContext.Group.Where(g => g.Name == groupName).Include(g => g.DefaultApplication).AsNoTracking().First();
            if (group == null)
            {
                return Json(JSONResult.ResponseError("Group not found"));
            }

            if (group.TopId == 0 ? user?.GroupId != group.Id : user?.Group?.TopId != group.Id)
            {
                return Json(JSONResult.ResponseError("Group should be top group"));
            }

            var curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == clientId)
                .Include(app => app.Cert).FirstOrDefault();
            if (curApplication is null)
            {
                return Json(JSONResult.ResponseError("Application not found"));
            }

            var respId = Guid.NewGuid().ToString("N");

            var samlResp = SamlUtil.GetRawSAMLResponse(user, curApplication, RequestUrl, RequestUrl, 
                TARGET, envelopReq?.Body.CasSamlRequest.AssertionArtiface ?? "", respId, 
                false, envelopReq?.Body.CasSamlRequest.RequestID);

            var casEnvlopeResponse = new CasEnvlopeResponse
            {
                Body = new CasEnvlopeResponse.CasSamlInnerResponse
                {
                    Response = samlResp.DocumentElement!
                }
            };

            return CasResult.GetResponse(casEnvlopeResponse, "xml");
        }
    }
}
