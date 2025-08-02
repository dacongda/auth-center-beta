using AuthCenter.Captcha;
using AuthCenter.Data;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(ILogger<UserController> logger, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IHttpContextAccessor httpContextAccessor, IConfiguration configuration) : Controller
    {
        private readonly ILogger<UserController> _logger = logger;
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
        private readonly IConfiguration _configuration = configuration;

        [HttpPost("login", Name = "Login")]
        public JSONResult Login(LoginUser loginUser)
        {
            var responseType = Request.Query["response_type"];
            var clientId = Request.Query["client_id"];

            // 获取组织与app
            var group = _authCenterDbContext.Group.Where(g => g.Name == loginUser.GroupName).Include(g => g.DefaultApplication).AsNoTracking().First();
            if (group == null)
            {
                return JSONResult.ResponseError("无此群组");
            }

            if (group.ParentId != 0)
            {
                return JSONResult.ResponseError("登陆必须为顶级群组");
            }

            if (group.DefaultApplication == null)
            {
                return JSONResult.ResponseError("需指定默认应用");
            }

            var curApplication = group.DefaultApplication;

            // 登陆至第三方
            if (loginUser.Type != "login")
            {
                curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == clientId.ToString()).Include(app => app.Cert).AsNoTracking().First();
                if (curApplication == null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }
            }

            var captchaItems = (from pItem in curApplication.ProviderItems
                                where pItem.Type == "Captcha"
                                select pItem).ToList();

            // 检查验证码
            if (captchaItems.Count > 0)
            {
                if (loginUser.CaptchaId == "" || loginUser.Code == "")
                {
                    return JSONResult.ResponseError("需要填写验证码");
                }

                var captchaItem = captchaItems.First();
                var cProvider = _authCenterDbContext.Provider.Find(captchaItem.Id);
                if (cProvider == null)
                {
                    return JSONResult.ResponseError("验证码提供商失效");
                }

                var captchaProvider = ICaptchaProvider.GetCaptchaProvider(cProvider, _cache);
                if (!captchaProvider.VerifyCode(loginUser.CaptchaId, loginUser.Code))
                {
                    return JSONResult.ResponseError("验证码错误");
                }
            }

            if (loginUser.LoginMethod == "Passkey")
            {
                loginUser.Name = _cache.GetString("WebAuthn:login:" + loginUser.Password) ?? "";
                if (loginUser.Name == "")
                {
                    return JSONResult.ResponseError("Passkey信息失效");
                }
            }

            var user = _authCenterDbContext.User.Where(u => u.Number == loginUser.Name).Include(p => p.Group).AsNoTracking().First();
            if (user == null || group.TopId == 0 ? user.GroupId != group.Id : user.Group.TopId != group.Id)
            {
                return JSONResult.ResponseError("无此用户");
            }

            user.loginApplication = curApplication.Id;

            if (loginUser.LoginMethod == "Password")
            {
                try
                {
                    if (!user.VerifyPassword(loginUser.Password))
                    {
                        return JSONResult.ResponseError("密码错误");
                    }
                }
                catch
                {
                    return JSONResult.ResponseError("密码错误");
                }
            }

            if (user.Group != null && loginUser.Type != "login")
            {
                var parentGroupNames = user.Group.Name.Split('/');
                var groupChainRoleList = _authCenterDbContext.Group
                    .Where(u => parentGroupNames.Contains(u.Name))
                    .Select(u => u.DefaultRoles).AsNoTracking().ToArray();
                foreach (var groupChainRole in groupChainRoleList)
                {
                    user.Roles = [.. user.Roles.Union(groupChainRole)];
                }
            }

            var request = _httpContextAccessor.HttpContext.Request;

            var url = request.Scheme + "://" + request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            string[] oauthType = ["code", "code id_token", "id_token", "id_token token", "code id_token token"];

            // 登陆系统管理页
            if (loginUser.Type == "login")
            {
                var tokenString = user.Id.ToString() + ":" + Guid.NewGuid().ToString();
                user.Group = null;

                _cache.SetString(tokenString, JsonSerializer.Serialize(user), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7),
                });

                return JSONResult.ResponseOk(
                    new LoginResult()
                    {
                        AccessToken = tokenString
                    });
            }
            else if (loginUser.Type == "oauth")
            {
                // 使用oidc code登陆
                var redirectUrl = Request.Query["redirect_uri"];
                var scope = Request.Query["scope"].ToString();
                var state = Request.Query["state"].ToString();
                var nonce = Request.Query["nonce"].ToString();

                var parsedRedirectUrl = new Uri(redirectUrl.ToString());

                var targetRedirect = curApplication.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == parsedRedirectUrl.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                Dictionary<string, string> dict = new();
                if (responseType.Contains("code"))
                {
                    var code = Guid.NewGuid().ToString();
                    code = Base64UrlEncoder.Encode(code);

                    _cache.SetString(code, JsonSerializer.Serialize(new
                    {
                        nonce,
                        state,
                        user,
                    }), new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120),
                    });

                    dict["code"] = code;
                }

                if (responseType.Contains("id_token") || responseType.Contains("token"))
                {
                    var tokenPack = TokenUtil.GenerateCodeToken(curApplication.Cert, user, curApplication, url, scope, nonce);
                    if (responseType.Contains("id_token"))
                    {
                        dict["id_token"] = tokenPack.IdToken ?? "";
                    }

                    if (responseType.Contains("token"))
                    {
                        dict["token"] = tokenPack.AccessToken ?? "";
                    }
                }

                return JSONResult.ResponseOk(dict);
            }
            else if (loginUser.Type == "saml")
            {
                var rawSamlRequest = Request.Query["SAMLRequest"];
                var samlRequest = SamlUtil.ParseSamlRequest(rawSamlRequest.ToString());

                var redirectUri = new Uri(samlRequest.AssertionConsumerServiceURL ?? "");
                var targetRedirect = curApplication.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == redirectUri.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                var respId = Guid.NewGuid().ToString("N");
                var samlResponse = SamlUtil.GetSAMLResponse(user, curApplication, url, frontEndUrl, samlRequest.AssertionConsumerServiceURL ?? "", samlRequest.Issuer, respId, samlRequest.ID);
                return JSONResult.ResponseOk(new
                {
                    samlResponse,
                    samlBindingType = samlRequest.ProtocolBinding,
                    redirectUrl = samlRequest.AssertionConsumerServiceURL
                });
            }

            return JSONResult.ResponseError("登陆类型错误");
        }

        [HttpPost("verifyUser", Name = "VerifyUser")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> VerifyUser(LoginUser loginUser)
        {
            if (loginUser.LoginMethod == "Password")
            {
                var user = await _authCenterDbContext.User.FirstOrDefaultAsync(u => u.Number == User.Identity.Name);
                try
                {
                    if (!user.VerifyPassword(loginUser.Password))
                    {
                        return JSONResult.ResponseError("认证失败");
                    }
                }
                catch
                {
                    return JSONResult.ResponseError("认证失败");
                }

            }
            else if (loginUser.LoginMethod == "Passkey")
            {
                var userId = await _cache.GetStringAsync("WebAuthn:verify:" + loginUser.Password);
                if (userId != User.Identity.Name)
                {
                    return JSONResult.ResponseError("认证失败");
                }
                await _cache.RemoveAsync("WebAuthn:verify:" + loginUser.Password);
            }
            else
            {
                return JSONResult.ResponseError("未知的验证方式");
            }

            var authId = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            await _cache.SetStringAsync($"Auth:Verify:{loginUser.Type}:{authId}", User.Identity.Name, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120),
            });

            return JSONResult.ResponseOk(new { verifyId = authId });
        }
    }
}
