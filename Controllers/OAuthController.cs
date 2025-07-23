using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using JWT;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using Newtonsoft.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthCenter.Controllers
{
    [Controller]
    [Route("api/[controller]")]
    public class OAuthController(IHttpContextAccessor httpContextAccessor, IDistributedCache cache, AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly HttpContext _httpContext = httpContextAccessor.HttpContext;
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        [HttpPost("token", Name ="oauth token")]
        [Authorize(AuthenticationSchemes = BasicAuthorizationHandler.BasicSchemeName, Roles = "app")]
        public IActionResult Token(string code, string? grant_type, string? redirect_uri, string? scopes)
        {
            Application? app = _httpContext.Items["application"] as Application;
            if (app == null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description =  "application not found"
                });
            }

            var jwtInfos = _cache.GetString(code);
            if (jwtInfos == null || jwtInfos == "")
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "code invalid or expired"
                });
            }

            var loginInfo = new { nonce = "", state = "", user = new User { Name = "", Number = "" }, redirect_uri = "" };
            var parsedLoginInfo = JsonConvert.DeserializeAnonymousType(jwtInfos, loginInfo, new JsonSerializerSettings { MissingMemberHandling=MissingMemberHandling.Ignore});

            if (parsedLoginInfo == null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "code invalid or expired"
                });
            }

            _cache.Remove(code);

            //var cert = _authCenterDbContext.Cert.Where(cert => cert.Id == app.CertId).First();
            if (app.Cert == null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "cert not found in application"
                });
            }

            var url = Request.Scheme + "://" + Request.Host.Value;
            var tokenPack = TokenUtil.GenerateCodeToken(app.Cert, parsedLoginInfo.user, app, url, scopes ?? "", parsedLoginInfo.nonce);

            return Json(new
            {
                access_token = tokenPack.AccessToken,
                refresh_token = tokenPack.RefreshToken,
                id_token = tokenPack.IdToken,
                token_type = "Bearer",
                expires_in = app.ExpiredSecond,
            });
        }
    }
}
