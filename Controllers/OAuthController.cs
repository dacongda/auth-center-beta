using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Providers.IdProvider;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthCenter.Controllers
{
    [Controller]
    [Route("api/[controller]")]
    public class OAuthController(IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;

        private string RequestUrl => ControllerUtils.GetFrontUrl(_configuration, Request);

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

            var loginInfo = new { nonce = "", state = "", user = new User { Name = "", Id = "" }, redirect_uri = "", codeChallenge = "", codeChallengeMethod = "" };
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

            if (string.IsNullOrEmpty(loginInfo.codeChallenge))
            {
                var codeVerifier = Request.Query["code_verifier"];
                var codeChallengeMatch = false;
                if (loginInfo.codeChallengeMethod == "plain" || loginInfo.codeChallenge is null)
                {
                    codeChallengeMatch = loginInfo.codeChallenge == codeVerifier;
                }
                else if (loginInfo.codeChallenge == "S256")
                {
                    var hashValue = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier.ToString()));

                    codeChallengeMatch = loginInfo.codeChallenge == Base64UrlTextEncoder.Encode(hashValue);
                }

                if (!codeChallengeMatch)
                {
                    Response.StatusCode = StatusCodes.Status400BadRequest;
                    return Json(new
                    {
                        error = "invalid_request",
                        error_description = "Code verifier incorrect"
                    });
                }
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

            var tokenPack = TokenUtil.GenerateCodeToken(code, app.Cert, parsedLoginInfo.user, app, RequestUrl, scopes ?? "", parsedLoginInfo.nonce);

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
                    request.TokenTypeHint = claims.FindFirst("token_type")!.Value;
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

        [HttpGet("getOAuthRequest", Name = "Get oauth request")]
        public async Task<JSONResult> GetRequest(int id, string type)
        {
            var provider = await _authCenterDbContext.Provider.FindAsync(id);
            if (provider is null || (provider.SubType != "OAuth2"
                && provider.SubType != "OIDC"
                && provider.SubType != "WeChat"))
            {
                return JSONResult.ResponseError("无此提供商");
            }

            var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[64];
            rng.GetBytes(bytes);
            var challenge = Base64UrlEncoder.Encode(bytes);
            var challengeMethod = "S256";

            byte[] stateBytes = new byte[32];
            rng.GetBytes(stateBytes);
            var state = Base64UrlEncoder.Encode(stateBytes);

            var tempId = Guid.NewGuid().ToString("N");

            await _cache.SetStringAsync($"Bind:OAuth:{tempId}", $"{challenge},{state}", new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300)
            });

            var responseType = provider.TokenType;
            if (String.IsNullOrEmpty(responseType))
            {
                responseType = "code";
            }

            var isWeChat = provider.SubType == "WeChat";
            var authorizationEndpoint = isWeChat && string.IsNullOrWhiteSpace(provider.AuthEndpoint)
                ? WeChat.DefaultAuthorizationEndpoint
                : provider.AuthEndpoint;
            if (string.IsNullOrWhiteSpace(authorizationEndpoint)
                || string.IsNullOrWhiteSpace(provider.ClientId))
            {
                return JSONResult.ResponseError("身份提供商配置不完整");
            }

            var redirectUrl = new UriBuilder(authorizationEndpoint);
            var queryData = new Dictionary<string, string>
            {
                [isWeChat ? "appid" : "client_id"] = provider.ClientId,
                ["redirect_uri"] = $"{RequestUrl}/auth/callback",
                ["response_type"] = isWeChat ? "code" : responseType
            };

            if (isWeChat)
            {
                queryData["scope"] = string.IsNullOrWhiteSpace(provider.Scopes)
                    ? "snsapi_login"
                    : provider.Scopes;
                redirectUrl.Fragment = "wechat_redirect";
            }
            else
            {
                var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(challenge));
                queryData["code_challenge"] = Base64UrlTextEncoder.Encode(challengeBytes);
                queryData["code_challenge_method"] = challengeMethod;
                if (!string.IsNullOrWhiteSpace(provider.Scopes))
                {
                    queryData["scope"] = provider.Scopes;
                }
            }

            queryData.Add("state", state);
            redirectUrl.Query = await new FormUrlEncodedContent(queryData).ReadAsStringAsync();

            return JSONResult.ResponseOk(new
            {
                redirectUrl = redirectUrl.ToString(),
                tempId
            });
        }

    }
}
