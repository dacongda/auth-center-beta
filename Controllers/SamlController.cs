using AuthCenter.Data;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SamlController(IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;
        private readonly IDistributedCache _cache = cache;

        private string RequestUrl => ControllerUtils.GetFrontUrl(_configuration, Request);

        [HttpGet("metadata/{clientId}", Name = "Saml metadata")]
        public IActionResult Metadata(string clientId)
        {
            var url = Request.Scheme + "://" + Request.Host.Value;

            var rawClientId = clientId.Split("-")[0];
            var application = _authCenterDbContext.Application.Where(app => app.ClientId == rawClientId).Include(app => app.Cert).FirstOrDefault();
            if (application == null)
            {
                return new NotFoundResult();
            }
            application.ClientId = clientId;

            var metadata = Utils.SamlUtil.GetSAMLMetadata(url, RequestUrl, application);

            return new ContentResult
            {
                Content = metadata.ToString(),
                ContentType = "text/xml",
                StatusCode = 200,
            };
        }

        [HttpPost("login-saml/{clientId}", Name = "LoginSAML Redirect")]
        public async Task<IActionResult> SAMLLogin(string clientId)
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            var samlRequest = Request.Form["SAMLRequest"];
            var relayState = Request.Form["RelayState"];

            var samlId = Guid.NewGuid().ToString();
            await _cache.SetStringAsync($"Login:SAML:SAMLID:{samlId}", $"{samlRequest}|{relayState}", new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300)
            });

            return Redirect($"{frontEndUrl}/auth/login-saml/{clientId}?samlId={samlId}");
        }

        [HttpGet("getSamlRequest", Name = "Get saml request")]
        public async Task<JSONResult> GetRequest(int id, bool isCompressed)
        {
            var provider = await _authCenterDbContext.Provider.FindAsync(id);
            if (provider is null || provider.SubType != "SAML")
            {
                return JSONResult.ResponseError("无此提供商");
            }

            var requestId = "a" + Guid.NewGuid().ToString("N");
            var providerMetadata = SamlUtil.ParseSamlMetaData(provider.Body!);
            var request = SamlUtil.GetSamlRequest(RequestUrl, providerMetadata.Location, providerMetadata.BindingType, requestId, isCompressed);
            _cache.SetString($"Login:SAML:Request{requestId}", provider.Name, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
            });

            var replayState = $"AC-{Guid.NewGuid().ToString("N")}";

            return JSONResult.ResponseOk(new
            {
                request,
                providerMetadata.Location,
                Binding = providerMetadata.BindingType,
                replayState
            });
        }
    }
}
