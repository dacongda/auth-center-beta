using AuthCenter.Captcha;
using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using OtpNet;
using System;
using System.Text.Json;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(ILogger<UserController> logger, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly ILogger<UserController> _logger = logger;
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
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

            // 处理MFA验证
            if (loginUser.IsMfaVerify)
            {
                var userObjStr = _cache.GetString($"mfa:verify:{loginUser.CaptchaId}") ?? "";
                if (String.IsNullOrEmpty(userObjStr)) return JSONResult.ResponseError("验证Id错误");

                var userObj = JsonSerializer.Deserialize<User>(userObjStr);

                if (!VerifyMfa(userObj, loginUser.LoginMethod, loginUser.Code, loginUser.Password))
                    return JSONResult.ResponseError("MFA认证失败");

                curApplication = _authCenterDbContext.Application.Find(userObj.loginApplication);

                return HandleUserLogin(loginUser, userObj, curApplication);
            }

            // 登陆至第三方
            if (loginUser.Type != "login")
            {
                curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == clientId.ToString()).Include(app => app.Cert).AsNoTracking().First();
                if (curApplication == null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }
            }

            var captchaVerifyRes = VerifyCaptchaCode(curApplication, loginUser.CaptchaId, loginUser.Code, false);
            if (captchaVerifyRes != "")
            {
                return JSONResult.ResponseError(captchaVerifyRes);
            }

            if (loginUser.LoginMethod == "Passkey")
            {
                loginUser.Name = _cache.GetString("WebAuthn:login:" + loginUser.Password) ?? "";
                if (loginUser.Name == "")
                {
                    return JSONResult.ResponseError("Passkey信息失效");
                }
            }

            var user = _authCenterDbContext.User.Where(u => u.Number == loginUser.Name).Include(p => p.Group).AsNoTracking().FirstOrDefault();
            if (user == null || group.TopId == 0 ? user?.GroupId != group.Id : user?.Group?.TopId != group.Id)
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

            // 要求MFA
            if (user.EnableEmailMfa || user.EnablePhoneMfa || user.EnableTotpMfa)
            {
                var avaliableMfa = new List<string>();
                if (user.EnableTotpMfa) avaliableMfa.Add("TOTP");
                if (user.EnableEmailMfa) avaliableMfa.Add("Email");
                if (user.EnablePhoneMfa) avaliableMfa.Add("Phone");

                var mfaVerifyId = Guid.NewGuid().ToString("N");
                _cache.SetString($"mfa:verify:{mfaVerifyId}", JsonSerializer.Serialize(user), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                });

                return JSONResult.ResponseOk(new
                {
                    RequireMfa = true,
                    PreferredMfa = user.PreferredMfaType,
                    AvaliableMfa = avaliableMfa,
                    MfaVerifyId = mfaVerifyId
                });
            }

            return HandleUserLogin(loginUser, user, curApplication);
        }


        private bool VerifyMfa(User user, string mfaType, string code, string mfaVerifyId)
        {
            if (mfaType == "TOTP")
            {
                byte[] bytes = Base32Encoding.ToBytes(user.TotpSecret);
                var totp = new Totp(bytes);

                long timeStampMatched;
                return totp.VerifyTotp(code, out timeStampMatched, VerificationWindow.RfcSpecifiedNetworkDelay);
            }
            else if (mfaType == "Email")
            {
                var secret = _cache.GetString($"verification:email:{mfaVerifyId}");

                var res = secret.Split(':');
                var validTime = Convert.ToInt32(res[1]);
                var ans = res[0];
                if (Convert.ToInt32(validTime) == 0)
                {
                    _cache.Remove($"verification:email:{mfaVerifyId}");
                    return false;
                }

                if (code != ans)
                {
                    _cache.SetStringAsync($"verification:email:{mfaVerifyId}", $"{code}:{validTime - 1}", new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                    });
                    return false;
                }

                return true;
            }
            else
            {
                var ans = _cache.GetString($"verification:code:{mfaVerifyId}");
                return code == ans;
            }
        }

        private JSONResult HandleUserLogin(LoginUser loginUser, User user, Application application)
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            if (frontEndUrl == null || frontEndUrl == "")
            {
                frontEndUrl = url;
            }

            var responseType = Request.Query["response_type"];
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

                var targetRedirect = application.RedirectUrls?
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
                    var tokenPack = TokenUtil.GenerateCodeToken(application.Cert, user, application, url, scope, nonce);
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
                var targetRedirect = application.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == redirectUri.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                var respId = Guid.NewGuid().ToString("N");
                var samlResponse = SamlUtil.GetSAMLResponse(user, application, url, frontEndUrl, samlRequest.AssertionConsumerServiceURL ?? "", samlRequest.Issuer, respId, samlRequest.ID);
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

            var authId = Base64UrlEncoder.Encode(Guid.NewGuid().ToByteArray());
            var keyId = $"Auth:Verify:{loginUser.Type}:{authId}";
            await _cache.SetStringAsync(keyId, User.Identity.Name, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120),
            });

            return JSONResult.ResponseOk(new { verifyId = authId });
        }

        [HttpPost("sendVerificationCode", Name = "SendVerificationCode")]
        [AllowAnonymous]
        public async Task<JSONResult> SendVerificationCode(VerificationCodeRequest request)
        {

            // 获取用户
            User? curUser;
            if (HttpContext.Items["user"] is not null)
            {
                curUser = HttpContext.Items["user"] as User;
            }
            else
            {
                var userObjStr = _cache.GetString($"mfa:verify:{request.VerifyId}") ?? "";
                if (String.IsNullOrEmpty(userObjStr)) return JSONResult.ResponseError("验证Id错误");

                curUser = JsonSerializer.Deserialize<User>(userObjStr);
            }

            // 应用为空时默认取用户的
            if (request.ApplicationId is null)
            {
                if (curUser is null)
                {
                    return JSONResult.ResponseError("未指定应用");
                }
                request.ApplicationId = curUser.loginApplication;
            }


            // 目的地为空是默认取用用户的
            if (request.Destination == "")
            {
                if (curUser is null)
                {
                    return JSONResult.ResponseError("未指定目的地址");
                }

                if (request.AuthType == "Email")
                {
                    request.Destination = curUser.Email ?? "";
                }

                if (request.AuthType == "Phone")
                {
                    request.Destination = curUser.Phone ?? "";
                }

                if (request.Destination == "")
                {
                    return JSONResult.ResponseError("未指定目的地址");
                }
            }

            var app = await _authCenterDbContext.Application.FindAsync(request.ApplicationId);
            if (app == null)
            {
                return JSONResult.ResponseError("认证失效");
            }

            var captchaVerifyRes = VerifyCaptchaCode(app, request.CaptchaId, request.CaptchaCode, true);
            if (captchaVerifyRes != "") {
                return JSONResult.ResponseError(captchaVerifyRes);
            }


            if (request.AuthType == "Email")
            {
                var mfaEnableId = Guid.NewGuid().ToString("N");
                var random = new Random();
                var code = random.Next(100000, 999999).ToString();

                var mailProviderItem = (from pItem in app.ProviderItems where pItem.Type == "Email" select pItem).FirstOrDefault();
                if (mailProviderItem is null)
                {
                    return JSONResult.ResponseError("无邮件提供商");
                }

                var provider = await _authCenterDbContext.Provider.FindAsync(mailProviderItem.ProviderId);
                if (provider == null)
                {
                    return JSONResult.ResponseError("无邮件提供商");
                }

                var sended = await _cache.GetStringAsync($"verification:code:{request.Destination}");
                if (sended == "1")
                {
                    return JSONResult.ResponseError("未过冷却期");
                }

                var body = provider.Body.Replace("%code%", code);
                Utils.EmailUtils.SendEmail(provider.ConfigureUrl, provider.Port.Value, provider.EnableSSL.Value, provider.ClientId, provider.ClientSecret, request.Destination, provider.Subject, body);
                await _cache.SetStringAsync($"verification:code:{request.Destination}", "1", new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(60),
                });

                await _cache.SetStringAsync($"verification:email:{mfaEnableId}", $"{code}:{3}", new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                });

                return JSONResult.ResponseOk(new { mfaEnableId });
            }
            else
            {
                return JSONResult.ResponseError("未实现");
            }
        }

        private string VerifyCaptchaCode(Application app, string captchaId, string captchaCode, bool mustVerify)
        {
            var captchaItems = (from pItem in app.ProviderItems
                                where pItem.Type == "Captcha"
                                select pItem).ToList();


            if (captchaItems.Count == 0)
            {
                return mustVerify ? "为保证安全，发送验证码必须指定一个验证码提供商" : "";
            }


            if (captchaId == "" || captchaCode == "")
            {
                return "需要填写验证码";
            }

            var captchaItem = captchaItems.First();
            var cProvider = _authCenterDbContext.Provider.Find(captchaItem.ProviderId);
            if (cProvider == null)
            {
                return "验证码提供商失效";
            }

            var captchaProvider = ICaptchaProvider.GetCaptchaProvider(cProvider, _cache);
            if (!captchaProvider.VerifyCode(captchaId, captchaCode))
            {
                return "验证码错误";
            }

            return "";
        }
    }
}
