using AuthCenter.Captcha;
using AuthCenter.Data;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CaptchaController(AuthCenterDbContext authCenterDbContext, IDistributedCache cache) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IDistributedCache _cache = cache;

        [HttpGet("getCaptcha", Name = "GetCaptcha")]
        public JSONResult GetCaptcha(int applicationId, int? width, int? height)
        {
            var app = _authCenterDbContext.Application.Find(applicationId);
            if (app == null)
            {
                return JSONResult.ResponseError("应用不存在");
            }

            var captchaItems = (from pItem in app.ProviderItems
                                where pItem.Type == "Captcha"
                                select pItem).ToList();

            if (!captchaItems.Any())
            {
                return JSONResult.ResponseError("应用无验证码提供商");
            }

            var captchaItem = captchaItems[0];
            if (captchaItem.Rule is null)
            {
                return JSONResult.ResponseError("应用无验证码提供商");
            }

            var captchaProvider = _authCenterDbContext.Provider.Find(captchaItem.ProviderId);
            if (captchaProvider == null)
            {
                return JSONResult.ResponseError("应用无验证码提供商");
            }

            if (captchaProvider.SubType == "Default")
            {
                var (code, res) = Utils.CaptchaUtils.GenerateCodeStr(captchaProvider.Port ?? 4, captchaItem.Rule[0]);

                var captchaImg = "";
                if (height is not null)
                {
                    captchaImg = Utils.CaptchaUtils.GenerateBase64Captcha(code, 35, 12, (int)height);
                }
                else
                {
                    captchaImg = Utils.CaptchaUtils.GenerateBase64Captcha(code, 35, 12);
                }

                // Use provider Id:captcha Id to prevent personate
                var captchaId = captchaProvider.Id.ToString() + ':' + Guid.NewGuid().ToString("N");

                _cache.SetString(captchaId, res, new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(2),
                });

                return JSONResult.ResponseOk(new
                {
                    captchaId,
                    captchaImg,
                });
            }

            return JSONResult.ResponseError("Unsupported subtype");
        }
    }
}
