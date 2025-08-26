using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Captcha
{
    public interface ICaptchaProvider
    {
        public bool VerifyCode(string captchaId, string code);
        public static ICaptchaProvider GetCaptchaProvider(Models.Provider provider, IDistributedCache cache)
        {
            if (provider.SubType == "Default")
            {
                return new DefaultCaptcha(provider.Id.ToString(), cache);
            }
            else if (provider.SubType == "Aliyun")
            {
                return new AliyunCaptcha(provider.ClientId ?? "", provider.ClientSecret ?? "", provider.ConfigureUrl ?? "");
            }

            throw new NotImplementedException();
        }
    }
}
