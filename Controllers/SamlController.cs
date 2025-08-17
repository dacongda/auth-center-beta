using AuthCenter.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SamlController(IHttpContextAccessor httpContextAccessor, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;

        [HttpGet("metadata/{clientId}", Name = "Saml metadata")]
        public IActionResult Metadata(string clientId)
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            var rawClientId = clientId.Split("-")[0];
            var application = _authCenterDbContext.Application.Where(app => app.ClientId == rawClientId).Include(app => app.Cert).FirstOrDefault();
            if (application == null)
            {
                return new NotFoundResult();
            }
            application.ClientId = clientId;

            var metadata = Utils.SamlUtil.GetSAMLMetadata(url, frontEndUrl, application);

            return new ContentResult
            {
                Content = metadata.ToString(),
                ContentType = "text/xml",
                StatusCode = 200,
            };
        }
    }
}
