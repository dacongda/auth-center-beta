using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthCenter.Controllers
{
    [Controller]
    [Route("api/[controller]")]
    public class OAuthController(IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;

        [HttpPost("token", Name = "Oauth token api")]
        [Authorize(AuthenticationSchemes = BasicAuthorizationHandler.BasicSchemeName, Roles = "app")]
        public IActionResult Token(string code, string? grant_type, string? redirect_uri, string? scopes)
        {
            Application? app = HttpContext.Items["application"] as Application;
            if (app == null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "application not found"
                });
            }

            var jwtInfos = _cache.GetString($"Login:OAuth:Code:{code}");
            if (jwtInfos == null || jwtInfos == "")
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "code invalid or expired"
                });
            }

            var loginInfo = new { nonce = "", state = "", user = new User { Name = "", Id = "" }, redirect_uri = "" };
            var parsedLoginInfo = JsonConvert.DeserializeAnonymousType(jwtInfos, loginInfo, new JsonSerializerSettings { MissingMemberHandling = MissingMemberHandling.Ignore });

            if (parsedLoginInfo == null)
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return Json(new
                {
                    error = "invalid_grant",
                    error_description = "code invalid or expired"
                });
            }

            _cache.Remove($"Login:OAuth:Code:{code}");

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
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }
            var tokenPack = TokenUtil.GenerateCodeToken(code, app.Cert, parsedLoginInfo.user, app, frontEndUrl, scopes ?? "", parsedLoginInfo.nonce);

            _cache.SetString($"Login:OAuth:Token:{code}", "1");

            return Json(new
            {
                access_token = tokenPack.AccessToken,
                refresh_token = tokenPack.RefreshToken,
                id_token = tokenPack.IdToken,
                token_type = "Bearer",
                expires_in = app.ExpiredSecond,
            });
        }

        [HttpPost("introspection", Name = "Oauth introspection api")]
        [Authorize(AuthenticationSchemes = BasicAuthorizationHandler.BasicSchemeName, Roles = "app")]
        public async Task<IActionResult> Introspection(IntrospectionRequest request)
        {
            var application = HttpContext.Items["application"] as Application;

            var tokenObj = new JwtSecurityToken(request.Token);
            try
            {
                var claims = TokenUtil.ValidateToken(request.Token, application, Request.GetDisplayUrl());

                if (request.TokenTypeHint == "")
                {
                    request.TokenTypeHint = claims.FindFirst("tokenType")!.Value;
                }

                var jti = claims.FindFirstValue("jit") ?? "";

                var cached = await _cache.GetStringAsync(jti.Replace($"-{request.TokenTypeHint}", ""));
                if (cached == null)
                {
                    throw new Exception();
                }

                var issueAt = new DateTimeOffset(tokenObj.IssuedAt).ToUnixTimeSeconds();
                var expiredAt = new DateTimeOffset(tokenObj.ValidTo).ToUnixTimeSeconds();

                return Json(new
                {
                    active = true,
                    sub = tokenObj.Subject,
                    aud = tokenObj.Audiences.FirstOrDefault(),
                    iss = tokenObj.Issuer,
                    jti,
                    token_type = request.TokenTypeHint,
                    iat = issueAt,
                    nbf = issueAt,
                    exp = expiredAt,
                    scope = claims.FindFirstValue("scope"),
                });
            }
            catch
            {
                return Json(new
                {
                    active = false
                });
            }
        }
    }
}
