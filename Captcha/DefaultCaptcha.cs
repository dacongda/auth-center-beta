using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Captcha
{
    public class DefaultCaptcha(string providerId, IDistributedCache cache) : ICaptchaProvider
    {
        private readonly IDistributedCache _cache = cache;
        private readonly string _providerId = providerId;

        public bool VerifyCode(string captchaId, string code)
        {
            var pId = captchaId.Split(":")[0];
            if (pId != _providerId)
            {
                return false;
            }

            var ans = _cache.GetString(captchaId);
            if (ans == null)
            {
                return false;
            }
            _cache.Remove(captchaId);

            return ans == code;
        }
    }
}
