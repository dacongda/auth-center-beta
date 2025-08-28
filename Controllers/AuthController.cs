using AuthCenter.Captcha;
using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.Providers.IdProvider;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
        private string RequestUrl => ControllerUtils.GetFrontUrl(_configuration, Request);

        [HttpPost("login", Name = "Login")]
        [Authorize(Roles = "admin,user")]
        [AllowAnonymous]
        public async Task<JSONResult> Login(LoginUser loginUser)
        {
            var responseType = Request.Query["response_type"];
            var clientId = Request.Query["client_id"];

            // fetch organization and default application
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

            // check MFA
            if (loginUser.IsMfaVerify)
            {
                var userObjStr = _cache.GetString($"mfa:verify:{loginUser.CaptchaId}") ?? "";
                if (String.IsNullOrEmpty(userObjStr)) return JSONResult.ResponseError("验证Id错误");

                var userObj = JsonSerializer.Deserialize<CachedUser>(userObjStr);
                if (userObj is null)
                {
                    return JSONResult.ResponseError("用户不存在");
                }

                var dbUser = _authCenterDbContext.User.Find(userObj.Id);
                if (dbUser is null)
                {
                    return JSONResult.ResponseError("用户不存在");
                }

                dbUser.LoginApplication = userObj.LoginApplication;
                if (!VerifyMfa(dbUser, loginUser.LoginMethod, loginUser.Code, loginUser.Password))
                    return JSONResult.ResponseError("MFA认证失败");

                curApplication = _authCenterDbContext.Application.Where(app => app.Id == userObj.LoginApplication).Include(app => app.Cert).FirstOrDefault();
                if (curApplication is null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }

                return HandleUserLogin(loginUser, dbUser, curApplication, userObj.LoginVia);
            }

            // Thirdpart login
            if (loginUser.Type != "login" && loginUser.Type != "bind")
            {
                var rawClientId = clientId.ToString().Split("-", 2)[0];
                curApplication = _authCenterDbContext.Application.Where(app => app.ClientId == rawClientId).Include(app => app.Cert).AsNoTracking().FirstOrDefault();
                if (curApplication == null)
                {
                    return JSONResult.ResponseError("应用不存在");
                }

                if (!curApplication.GroupIds.Contains(group.Id))
                {
                    return JSONResult.ResponseError("组织不在应用许可列表内");
                }
            }

            // normal login process
            if (loginUser.LoginMethod != "ThirdPart")
            {
                var captchaVerifyRes = VerifyCaptchaCode(curApplication, loginUser.CaptchaId, loginUser.Code, false);
                if (captchaVerifyRes != "")
                {
                    return JSONResult.ResponseError(captchaVerifyRes);
                }
            }

            // Process passkey
            var verifyPassword = false;
            if (loginUser.LoginMethod == "Passkey")
            {
                loginUser.Name = _cache.GetString("WebAuthn:login:" + loginUser.Password) ?? "";
                if (loginUser.Name == "")
                {
                    return JSONResult.ResponseError("Passkey信息失效");
                }
                _cache.Remove("WebAuthn:login:" + loginUser.Password);
                verifyPassword = true;
            }

            // Login through third part
            UserInfo? userInfo = null;
            var loginVia = "default";
            if (loginUser.LoginMethod == "ThirdPart")
            {
                var idProvider = _authCenterDbContext.Provider.Where(p => p.Name == loginUser.Code).FirstOrDefault();
                if (idProvider is null)
                {
                    return JSONResult.ResponseError("身份提供商不存在");
                }

                var providerItem = curApplication.ProviderItems.Find(pi => pi.ProviderId == idProvider.Id);
                var idProviderUtil = IIdProvider.GetIdProvider(idProvider, RequestUrl, $"{RequestUrl}/auth/callback", loginUser.CaptchaId, _cache);

                userInfo = await idProviderUtil.getUserInfo(loginUser.Password, loginUser.State, loginUser.TempId);
                var userId = _authCenterDbContext.UserThirdpartInfos
                    .Where(uti => uti.ProviderName == idProvider.Name && uti.ThirdPartId == userInfo.Id)
                    .Select(uti => uti.UserId).FirstOrDefault();

                if (loginUser.Type == "bind")
                {
                    userId = User.Identity?.Name;
                }

                if (userId is null)
                {
                    return JSONResult.ResponseError("用户不存在");
                }

                loginUser.Name = userId;
                loginVia = idProvider.Name;
                verifyPassword = true;
            }

            // fetch user
            var user = _authCenterDbContext.User.Where(u => u.Id == loginUser.Name).Include(p => p.Group).AsNoTracking().FirstOrDefault();
            if (user == null || group.TopId == 0 ? user?.GroupId != group.Id : user?.Group?.TopId != group.Id)
            {
                return JSONResult.ResponseError("无此用户");
            }

            // process bind third part
            if (loginUser.Type == "bind")
            {
                if (userInfo == null)
                {
                    return JSONResult.ResponseError("无此用户");
                }

                var userThirdPartInfo = new UserThirdpartInfo
                {
                    ProviderName = loginUser.Code,
                    UserId = user.Id,
                    ThirdPartId = userInfo.Id,
                    ThirdPartName = userInfo.Name,
                };

                _ = await _authCenterDbContext.AddAsync(userThirdPartInfo);
                _authCenterDbContext.SaveChanges();
                return JSONResult.ResponseOk("成功");
            }

            // Check user's password
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
                verifyPassword = true;
            }

            if (!verifyPassword)
            {
                return JSONResult.ResponseError("密码错误");
            }

            // If user enable MFA, check mfa
            if ((user.EnableEmailMfa || user.EnablePhoneMfa || user.EnableTotpMfa) && loginUser.LoginMethod != "Passkey")
            {
                var avaliableMfa = new List<string>();
                if (user.EnableTotpMfa) avaliableMfa.Add("TOTP");
                if (user.EnableEmailMfa) avaliableMfa.Add("Email");
                if (user.EnablePhoneMfa) avaliableMfa.Add("Phone");

                CachedUser cachedUser = new()
                {
                    Id = user.Id,
                    LoginApplication = curApplication.Id,
                    LoginVia = loginVia,
                    Email = user.Email ?? "",
                    Phone = user.Phone ?? "",
                };

                var mfaVerifyId = Guid.NewGuid().ToString("N");
                _cache.SetString($"mfa:verify:{mfaVerifyId}", JsonSerializer.Serialize(cachedUser), new DistributedCacheEntryOptions
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

            return HandleUserLogin(loginUser, user, curApplication, loginVia);
        }

        private bool VerifyMfa(User user, string mfaType, string code, string mfaVerifyId)
        {
            if (mfaType == "TOTP")
            {
                byte[] bytes = Base32Encoding.ToBytes(user.TotpSecret);
                var totp = new Totp(bytes);

                return totp.VerifyTotp(code, out long timeStampMatched, VerificationWindow.RfcSpecifiedNetworkDelay);
            }
            else if (mfaType == "Email")
            {
                var secret = _cache.GetString($"verification:email:{mfaVerifyId}");
                if (string.IsNullOrEmpty(secret))
                {
                    return false;
                }

                var res = secret.Split(':');
                var validTime = Convert.ToInt32(res?[1]);
                var ans = res?[0];
                var destination = res?[2];
                if (user.Email != destination)
                {
                    return false;
                }
                if (Convert.ToInt32(validTime) == 0)
                {
                    _cache.Remove($"verification:email:{mfaVerifyId}");
                    return false;
                }

                if (code != ans)
                {
                    _cache.SetStringAsync($"verification:email:{mfaVerifyId}", $"{ans}:{validTime - 1}:{destination}", new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                    });
                    return false;
                }

                return true;
            }
            else if (mfaType == "Phone")
            {
                var ans = _cache.GetString($"verification:code:{mfaVerifyId}");
                return code == ans;
            }
            else if (mfaType == "RecoveryCode")
            {
                return code == user.RecoveryCode;
            }

            return false;
        }

        private JSONResult HandleUserLogin(LoginUser loginUser, User user, Application application, string loginVia)
        {
            string clientIp = Request.Headers["X-Forwarded-For"].FirstOrDefault() ?? "";

            // 如果为空，则使用 REMOTE_ADDR
            if (string.IsNullOrEmpty(clientIp))
            {
                clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
            }

            var userSession = new UserSession
            {
                UserId = user.Id,
                LoginType = loginUser.Type,
                LoginMethod = loginUser.LoginMethod,
                LoginApplication = application.Name ?? "",
                LoginIp = clientIp,
                LoginVia = loginVia,
                ExpiredAt = DateTime.UtcNow.AddDays(7)
            };

            var responseType = Request.Query["response_type"];

            // Login to manage system
            if (loginUser.Type == "login")
            {
                var tokenString = user.Id.ToString() + ":" + Guid.NewGuid().ToString();

                CachedUser cachedUser = new CachedUser
                {
                    Id = user.Id,
                    LoginApplication = application.Id,
                    LoginVia = loginVia,
                };

                _cache.SetString($"Login:Auth:{tokenString}", JsonSerializer.Serialize(cachedUser), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7),
                });

                userSession.SessionId = tokenString;
                userSession.LoginToken = tokenString;

                _authCenterDbContext.UserSessions.Add(userSession);
                _authCenterDbContext.SaveChangesAsync();

                return JSONResult.ResponseOk(
                    new LoginResult()
                    {
                        AccessToken = tokenString
                    });
            }

            if (user.Group is null)
            {
                user.Group = _authCenterDbContext.Group.Find(user.GroupId);
            }

            var parentGroupNames = user.Group!.Name.Split('/');
            var groupChainRoleList = _authCenterDbContext.Group
                .Where(u => parentGroupNames.Contains(u.Name))
                .Select(u => u.DefaultRoles).AsNoTracking().ToArray();

            foreach (var groupChainRole in groupChainRoleList)
            {
                user.Roles = [.. user.Roles.Union(groupChainRole)];
            }


            if (loginUser.Type == "oauth")
            {
                // Oauth / oidc login
                var redirectUrl = Request.Query["redirect_uri"];
                var scope = Request.Query["scope"].ToString();
                var state = Request.Query["state"].ToString();
                var nonce = Request.Query["nonce"].ToString();

                var parsedRedirectUrl = new Uri(redirectUrl.ToString());

                var targetRedirect = application.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == parsedRedirectUrl.Host)
                    .FirstOrDefault();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                Dictionary<string, string> dict = [];

                var code = Guid.NewGuid().ToString();
                code = Base64UrlEncoder.Encode(code).Replace("-", "X");

                if (responseType.Contains("code"))
                {
                    var codeChallengeMethod = Request.Query["code_challenge_method"];
                    var codeChallenge = Request.Query["code_challenge"];

                    _cache.SetString($"Login:OAuth:Code:{code}", JsonSerializer.Serialize(new
                    {
                        nonce,
                        state,
                        codeChallengeMethod,
                        codeChallenge,
                        user,
                    }), new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120),
                    });

                    dict["code"] = code;
                }

                if (responseType.Contains("id_token") || responseType.Contains("token"))
                {
                    var tokenPack = TokenUtil.GenerateCodeToken(code, application.Cert!, user, application, RequestUrl, scope, nonce);
                    if (responseType.Contains("id_token"))
                    {
                        dict["id_token"] = tokenPack.IdToken ?? "";
                    }

                    if (responseType.Contains("token"))
                    {
                        dict["token"] = tokenPack.AccessToken ?? "";
                    }

                    if (!responseType.Contains("code"))
                    {
                        _cache.SetString($"Login:OAuth:Code:{code}", "1", new DistributedCacheEntryOptions
                        {
                            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(application.ExpiredSecond),
                        });
                    }
                }

                userSession.SessionId = code;
                userSession.LoginToken = "";

                _authCenterDbContext.UserSessions.Add(userSession);
                _authCenterDbContext.SaveChangesAsync();

                return JSONResult.ResponseOk(dict);
            }
            else if (loginUser.Type == "saml")
            {
                // SAML login
                var rawSamlRequest = Request.Query["SAMLRequest"];
                var rawRelayState = Request.Query["RelayState"];
                var samlBinding = "";
                if (String.IsNullOrEmpty(rawSamlRequest))
                {
                    var samlId = Request.Query["samlId"];
                    var rawQuery = _cache.GetString($"Login:SAML:SAMLID:{samlId}");
                    if (rawQuery is null)
                    {
                        return JSONResult.ResponseError("请求参数错误");
                    }
                    rawSamlRequest = rawQuery.Split("|")[0];
                    rawRelayState = rawQuery.Split("|")[1];
                    samlBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
                }

                var samlRequest = SamlUtil.ParseSamlRequest(rawSamlRequest.ToString());

                var redirectUri = new Uri(samlRequest.AssertionConsumerServiceURL ?? "");
                var targetRedirect = application.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == redirectUri.Host)
                    .First();
                if (targetRedirect == null)
                {
                    return JSONResult.ResponseError("目标地址不在许可地址内");
                }

                if (!application.SamlAudiences.Contains(samlRequest.Issuer))
                {
                    return JSONResult.ResponseError("请求issuer不在许可名单内");
                }

                var respId = Guid.NewGuid().ToString("N");

                foreach (var item in application.SamlRedirects)
                {
                    if (item.Issuer == samlRequest.Issuer)
                    {
                        samlRequest.Issuer = item.Issuer;
                        samlRequest.AssertionConsumerServiceURL = item.RedirectUrl;
                    }
                }

                var samlResponse = SamlUtil.GetSAMLResponse(user, application, RequestUrl,
                    RequestUrl, samlRequest.AssertionConsumerServiceURL ?? "",
                    samlRequest.Issuer, respId, application.SamlEncrypt, samlRequest.ID);

                userSession.SessionId = respId;
                userSession.LoginToken = "";

                _authCenterDbContext.UserSessions.Add(userSession);
                _authCenterDbContext.SaveChangesAsync();

                if (samlRequest.ProtocolBinding != "")
                {
                    samlBinding = samlRequest.ProtocolBinding;
                }

                return JSONResult.ResponseOk(new
                {
                    samlResponse,
                    relayState = rawRelayState,
                    samlBindingType = samlBinding,
                    redirectUrl = samlRequest.AssertionConsumerServiceURL
                });
            }

            return JSONResult.ResponseError("登陆类型错误");
        }
        [HttpPost("register", Name = "Register user")]
        public async Task<JSONResult> Register(RegisterUser registerUser)
        {
            // 获取组织与app
            var group = await _authCenterDbContext.Group.Where(g => g.Name == registerUser.GroupName).Include(g => g.DefaultApplication).AsNoTracking().FirstOrDefaultAsync();
            if (group == null)
            {
                return JSONResult.ResponseError("无此群组");
            }

            if (group.DisableSignup)
            {
                return JSONResult.ResponseError("此应用禁止注册");
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

            var captchaVerifyRes = VerifyCaptchaCode(curApplication, registerUser.CaptchaId, registerUser.Code, false);
            if (captchaVerifyRes != "")
            {
                return JSONResult.ResponseError(captchaVerifyRes);
            }

            if (await _authCenterDbContext.User.Where(u => u.Id == registerUser.Id || (u.Email != null && u.Email == registerUser.Email) || (u.Phone != null && u.Phone == registerUser.Phone)).AnyAsync())
            {
                return JSONResult.ResponseError("已有用户用此ID注册或邮箱/手机冲突");
            }

            User user = new User { Id = registerUser.Id, Name = registerUser.Name, Email = registerUser.Email, Phone = registerUser.Phone, GroupId = group.Id };

            var emailProviderItem = curApplication.ProviderItems.Where(pItem => pItem.Type == "Email").FirstOrDefault();
            if (emailProviderItem != null && emailProviderItem.Rule.Contains("Register"))
            {
                if (!VerifyMfa(user, "Email", registerUser.EmailVerifyCode, registerUser.EmailVerifyId))
                {
                    return JSONResult.ResponseError("邮箱验证失败");
                }

                user.EmailVerified = true;
            }

            var phoneProviderItem = curApplication.ProviderItems.Where(pItem => pItem.Type == "Phone").FirstOrDefault();
            if (phoneProviderItem != null && phoneProviderItem.Rule.Contains("Register"))
            {
                if (!VerifyMfa(user, "Phone", registerUser.PhoneVerifyCode, registerUser.PhoneVerifyId))
                {
                    return JSONResult.ResponseError("手机验证失败");
                }

                user.EmailVerified = true;
            }

            user.Roles = group.DefaultRoles;
            user.Password = BCrypt.Net.BCrypt.HashPassword(registerUser.Password);

            _authCenterDbContext.User.Add(user);
            await _authCenterDbContext.SaveChangesAsync();

            return JSONResult.ResponseOk();
        }
        [HttpPost("logout", Name = "Logout")]
        [Authorize(Roles = "admin,user")]
        public async Task<IActionResult> Logout()
        {
            var token = Request.Headers.Authorization.ToString();
            if (token.Split(" ").Length == 2)
            {
                Response.Headers.CacheControl = "no-store";

                if (String.IsNullOrEmpty(Request.Form["id_token_hint"]))
                {
                    Response.StatusCode = 400;
                    return Json(new
                    {
                        error = "invalid_request",
                        error_description = "empty id token"
                    });
                }

                var app = HttpContext.Items["application"] as Application;
                var claims = TokenUtil.ValidateToken(token, app, Request.GetDisplayUrl());
                var jti = claims.FindFirstValue("jit") ?? "";
                var tokenId = jti.Split("-")[0];

                if (token.StartsWith("Bearer"))
                {
                    var tokenIdHeader = HttpContext.Items["tokenId"] as string ?? "";

                    if (tokenIdHeader != tokenId)
                    {
                        Response.StatusCode = 400;
                        return Json(new
                        {
                            error = "invalid_token",
                            error_description = "Token not belongs to current user"
                        });
                    }
                }

                var tokenAffected = await _authCenterDbContext.UserSessions.Where(us => us.SessionId == tokenId).ExecuteDeleteAsync();
                if (tokenAffected == 0)
                {
                    Response.StatusCode = 400;
                    return Json(new
                    {
                        error = "invalid_token",
                        error_description = "Fail due to db error"
                    });
                }
                await _cache.RemoveAsync($"Login:OAuth:Token:{token}");

                var redirectUrl = Request.Form["post_logout_redirect_uri"];
                if (!String.IsNullOrEmpty(redirectUrl))
                {
                    var parsedRedirectUrl = new Uri(redirectUrl!);
                    var targetRedirect = app!.RedirectUrls?
                    .Where(allowedUrl => (new Uri(allowedUrl)).Host == parsedRedirectUrl.Host)
                    .FirstOrDefault();
                    if (targetRedirect == null)
                    {
                        Response.StatusCode = 400;
                        return Json(new
                        {
                            error = "invalid_token",
                            error_description = "redirect url not in allow list"
                        });
                    }

                    var redirect = new UriBuilder(parsedRedirectUrl);
                    var state = Request.Form["state"].FirstOrDefault();
                    if (!String.IsNullOrEmpty(state))
                    {
                        var queryBuilder = new QueryBuilder(QueryHelpers.ParseQuery(parsedRedirectUrl.Query));
                        queryBuilder.Add("state", state);
                        redirect.Query = queryBuilder.ToString();
                    }

                    return Redirect(redirect.ToString());
                }

                return Ok();
            }

            var affected = await _authCenterDbContext.UserSessions.Where(us => us.SessionId == token).ExecuteDeleteAsync();
            if (affected == 0)
            {
                return Json(JSONResult.ResponseError("注销失败"));
            }
            await _cache.RemoveAsync($"Login:Auth:{token}");

            return Json(JSONResult.ResponseOk());
        }

        [HttpPost("verifyUser", Name = "VerifyUser")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> VerifyUser(LoginUser loginUser)
        {
            if (loginUser.LoginMethod == "Password")
            {
                var user = await _authCenterDbContext.User.FirstOrDefaultAsync(u => u.Id == User.Identity!.Name);
                if (user is null)
                {
                    return JSONResult.ResponseError("无此用户");
                }

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
                if (userId != User.Identity!.Name)
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
            await _cache.SetStringAsync(keyId, User.Identity!.Name!, new DistributedCacheEntryOptions
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
            User? curUser = null;
            if (HttpContext.Items["user"] is not null)
            {
                curUser = HttpContext.Items["user"] as User;
            }
            else if (request.VerifyId != "")
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
                request.ApplicationId = curUser.LoginApplication;
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
            if (captchaVerifyRes != "")
            {
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

                var body = provider.Body!.Replace("%code%", code);
                EmailUtils.SendEmail(provider.ConfigureUrl!, provider.Port!.Value, provider.EnableSSL!.Value, provider.ClientId!, provider.ClientSecret!, request.Destination, provider.Subject!, body);
                await _cache.SetStringAsync($"verification:code:{request.Destination}", "1", new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(60),
                });

                await _cache.SetStringAsync($"verification:email:{mfaEnableId}", $"{code}:{3}:{request.Destination}", new DistributedCacheEntryOptions
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

        [HttpPost("sendForgetPasswordLink", Name = "SendForgetPasswordLink")]
        [AllowAnonymous]
        public async Task<JSONResult> SendForgetPasswordLink(VerificationCodeRequest request)
        {
            var emailVerifier = new EmailAddressAttribute();
            if (!emailVerifier.IsValid(request.Destination))
            {
                return JSONResult.ResponseError("邮件地址不正确");
            }

            var app = await _authCenterDbContext.Application.Where(a => a.Id == request.ApplicationId).Include(a => a.Cert).FirstOrDefaultAsync();
            if (app == null)
            {
                return JSONResult.ResponseError("应用不存在");
            }
            var res = VerifyCaptchaCode(app, request.CaptchaId, request.CaptchaCode, true);
            if (res != "")
            {
                return JSONResult.ResponseError(res);
            }

            var mProviderItem = (from pItem in app.ProviderItems
                                 where pItem.Type == "Email" && pItem.Rule.Contains("ForgetPassword")
                                 select pItem).FirstOrDefault();
            if (mProviderItem == null)
            {
                return JSONResult.ResponseError("邮件提供商不存在或不支持忘记密码");
            }

            var mProvider = await _authCenterDbContext.Provider.FindAsync(mProviderItem.ProviderId);
            if (mProvider == null)
            {
                return JSONResult.ResponseError("邮件提供商不存在或不支持忘记密码");
            }

            var user = await _authCenterDbContext.User.Where(u => u.Email == request.Destination).Include(u => u.Group).FirstOrDefaultAsync();
            if (user == null || user.GroupId == null)
            {
                return JSONResult.ResponseError("用户不存在");
            }

            if (!app.GroupIds.Any(item => item == user.GroupId))
            {
                return JSONResult.ResponseError("用户不存在");
            }

            //var url = Request.Scheme + "://" + Request.Host.Value;
            //var frontEndUrl = _configuration["FrontEndUrl"] ?? "";
            //if (frontEndUrl == null || frontEndUrl == "")
            //{
            //    frontEndUrl = url;
            //}

            var tokenId = Guid.NewGuid().ToString();
            var cert = app.Cert!;
            var certKey = cert.ToSecurityKey();

            var signingCredentials = new SigningCredentials(certKey, $"{cert.CryptoAlgorithm}{cert.CryptoSHASize}");

            app.AccessExpiredSecond = 300;
            var forgetToken = TokenUtil.GenerateToken(tokenId, user, app, signingCredentials, "forget_password", [], RequestUrl, "");

            await _cache.SetStringAsync($"Login:Forget:Token:{tokenId}", "1", new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300)
            });

            var resetLink = $"{RequestUrl}/auth/confirm-forget/{user.Group!.Name}?token={forgetToken}";
            var body = mProvider.LinkBody?.Replace("%link%", resetLink) ?? "";

            EmailUtils.SendEmail(mProvider.ConfigureUrl!,
                mProvider.Port!.Value,
                mProvider.EnableSSL!.Value,
                mProvider.ClientId!,
                mProvider.ClientSecret!,
                request.Destination,
                mProvider.Subject!,
                body);

            return JSONResult.ResponseOk();
        }

        [HttpPost("resetPassword", Name = "ResetPassword")]
        [AllowAnonymous]
        public async Task<JSONResult> ResetPassword(ResetPasswordRequest request)
        {
            var tokenObj = new JwtSecurityToken(request.ResetToken);

            var jti = tokenObj.Claims.FirstOrDefault(c => c.Type == "jti")?.Value ?? "";

            var isValid = await _cache.GetStringAsync($"Login:Forget:Token:{jti}");
            if (isValid == null)
            {
                return JSONResult.ResponseError("链接已失效");
            }

            var clientId = tokenObj.Audiences.First();
            if (clientId == null)
            {
                return JSONResult.ResponseError("应用不存在");
            }

            var app = _authCenterDbContext.Application.Where(app => app.ClientId == clientId).Include(p => p.Cert).First();

            try
            {
                _ = TokenUtil.ValidateToken(request.ResetToken!, app, Request.GetDisplayUrl());
            }
            catch
            {
                return JSONResult.ResponseError("应用不存在");
            }

            var user = _authCenterDbContext.User.Where(user => user.Id == tokenObj.Subject).Include(p => p.Group).First();
            if (user == null)
            {
                return JSONResult.ResponseError("用户不存在");
            }

            user.Password = BCrypt.Net.BCrypt.HashPassword(request.Password);
            var affected = await _authCenterDbContext.User.Where(u => u.Id == user.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.Password, user.Password));

            if (affected != 1)
            {
                return JSONResult.ResponseError("重置失败");
            }

            _ = _cache.RemoveAsync($"Login:Forget:Token:{jti}");

            return JSONResult.ResponseOk();
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


            if (captchaId == "" && captchaCode == "")
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

        [HttpPost("revokeToken", Name = "Revoke user token")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> RevokeSession([FromBody] dynamic data)
        {
            dynamic dynParam = Newtonsoft.Json.JsonConvert.DeserializeObject(Convert.ToString(data));
            var sessionId = (string)dynParam.sessionId;
            if (sessionId == null)
            {
                return JSONResult.ResponseError("参数校验失败");
            }

            var userSession = await _authCenterDbContext.UserSessions.FindAsync(sessionId);
            if (userSession == null)
            {
                return JSONResult.ResponseError("删除失败");
            }

            if (!User.IsInRole("admin") && (userSession.UserId != User.Identity?.Name))
            {
                return JSONResult.ResponseError("删除失败");
            }

            _authCenterDbContext.UserSessions.Remove(userSession);

            if (userSession.LoginType == "login")
            {
                await _cache.RemoveAsync($"Login:Auth:{sessionId}");
            }
            else if (userSession.LoginType == "oauth")
            {
                await _cache.RemoveAsync($"Login:OAuth:Token:{sessionId}");
            }

            _ = await _authCenterDbContext.SaveChangesAsync();

            return JSONResult.ResponseOk();
        }
    }
}
