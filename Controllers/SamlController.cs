using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using JWT.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection.Metadata;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SamlController(IHttpContextAccessor httpContextAccessor, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration)
    {
        private readonly HttpContext _httpContext = httpContextAccessor.HttpContext;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration=configuration;

        [HttpGet("metadata/{clientId}", Name="Saml metadata")]
        public IActionResult Metadata(string clientId)
        {
            var request = _httpContext.Request;

            var url = request.Scheme + "://" + request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            var application = _authCenterDbContext.Application.Where(app => app.ClientId == clientId).Include(app => app.Cert).First();
            if (application == null)
            {
                return new NotFoundResult();
            }

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
