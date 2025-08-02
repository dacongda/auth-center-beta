using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using OtpNet;
using System.Security.Cryptography;
using System.Text;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "admin,user")]
    public class MfaController(IDistributedCache cache, AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly IDistributedCache _cache = cache;
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        [HttpPost("enableMfaSetup", Name = "EnableMfaSetup")]
        public async Task<JSONResult> EnableMfaSetup(WebAuthnRequest<string> request)
        {
            var userId = await _cache.GetStringAsync($"Auth:Verify:MFA:{request.CacheOptionId}");
            if (userId != User.Identity.Name)
            {
                return JSONResult.ResponseError("认证失效");
            }

            if (request.RequestValue == "TOTP")
            {
                byte[] key = KeyGeneration.GenerateRandomKey();

                var base32String = Base32Encoding.ToString(key);
                var base32Bytes = Base32Encoding.ToBytes(base32String);

                var totpUri = new OtpUri(OtpType.Totp, base32Bytes, User.Identity.Name, issuer: "AuthCenter");
                var mfaEnableId = Guid.NewGuid().ToString("N");

                await _cache.SetStringAsync("mfa:enable:" + mfaEnableId, base32String, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                });

                return JSONResult.ResponseOk(new { totpUri = totpUri.ToUri(), secret = base32String, mfaEnableId });
            }
            else if (request.RequestValue == "Email")
            {
                var mfaEnableId = Guid.NewGuid().ToString("N");
                var random = new Random();
                var code = random.Next(100000, 999999).ToString();

                var curUser = HttpContext.Items["user"] as User;

                var app = await _authCenterDbContext.Application.FindAsync(curUser.loginApplication);
                if (app == null)
                {
                    return JSONResult.ResponseError("认证失效");
                }

                var mailProviderItem = (from pItem in app.ProviderItems where pItem.Type == "Mail" select pItem).FirstOrDefault();
                if (mailProviderItem is null)
                {
                    return JSONResult.ResponseError("无邮件提供商");
                }

                var provider = await _authCenterDbContext.Provider.FindAsync(mailProviderItem.Id);
                if (provider == null)
                {
                    return JSONResult.ResponseError("无邮件提供商");
                }

                var body = provider.Body.Replace("%code%", code);
                Utils.EmailUtils.SendEmail(provider.ConfigureUrl, provider.Port.Value, provider.EnableSSL.Value, provider.ClientId, provider.ClientSecret, curUser.Email, provider.Subject, body);

                await _cache.SetStringAsync("mfa:enable:" + mfaEnableId, code, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300),
                });
            }

            return JSONResult.ResponseError("并未实现");
        }

        [HttpPost("enableMfaVerify", Name = "EnableMfaVerify")]
        public async Task<JSONResult> EnableMfaVerify(WebAuthnRequest<string> request)
        {
            var user = HttpContext.Items["user"] as User;
            var secret = await _cache.GetStringAsync("mfa:ena，zble:" + request.CacheOptionId);
            if (String.IsNullOrEmpty(secret))
            {
                return JSONResult.ResponseError("认证失效");
            }

            if (request.AuthType == "TOTP")
            {
                byte[] bytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(bytes);

                long timeStampMatched;
                if (!totp.VerifyTotp(request.RequestValue, out timeStampMatched, VerificationWindow.RfcSpecifiedNetworkDelay))
                {
                    return JSONResult.ResponseError("认证失效");
                }

                user.TotpSecret = secret;
                user.EnableTotpMfa = true;
            }
            else if (request.AuthType == "Email")
            {
                if(secret != request.RequestValue)
                {
                    return JSONResult.ResponseError("认证失效");
                }
            }

            var recoveryCode = "";
            if (String.IsNullOrEmpty(user.RecoveryCode))
            {
                recoveryCode = Guid.NewGuid().ToString();
                recoveryCode += "-" + Guid.NewGuid().ToString();

                recoveryCode = recoveryCode.ToUpper();
                user.RecoveryCode = recoveryCode;
            }


            var effected = await _authCenterDbContext.User.Where(u => u.Number == user.Number).ExecuteUpdateAsync(
                s => s.SetProperty(u => u.TotpSecret, user.TotpSecret)
                .SetProperty(u => u.EnableTotpMfa, user.EnableTotpMfa)
                .SetProperty(u => u.EnableEmailMfa, user.EnableEmailMfa)
                .SetProperty(u => u.EnablePhoneMfa, user.EnablePhoneMfa)
                .SetProperty(u => u.RecoveryCode, user.RecoveryCode));

            if (effected == 0)
            {
                return JSONResult.ResponseError("更新未执行");
            }

            return JSONResult.ResponseOk(new
            {
                recoveryCode,
            });
        }
    }
}
