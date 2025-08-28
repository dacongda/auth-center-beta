using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace AuthCenter.Captcha
{
    public interface ICaptchaProvider
    {
        public bool VerifyCode(string captchaId, string code, string userIp);
        public static ICaptchaProvider GetCaptchaProvider(Models.Provider provider, IDistributedCache cache)
        {
            if (provider.SubType == "Default")
            {
                return new DefaultCaptcha(provider.Id.ToString(), cache);
            }
            else if (provider.SubType == "Aliyun")
            {
                return new AliyunCaptcha(provider.ClientId ?? "", provider.ClientSecret ?? "", provider.SceneId ?? "");
            }
            else if (provider.SubType == "ReCaptchaV2")
            {
                return new ReCaptchaV2(provider.ClientId ?? "", provider.ClientSecret ?? "");
            }
            else if (provider.SubType == "HCaptcha")
            {
                return new HCaptcha(provider.ClientId ?? "", provider.ClientSecret ?? "");
            }
            else if (provider.SubType == "Cloudflare")
            {
                return new Cloudflare(provider.ClientId ?? "", provider.ClientSecret ?? "");
            }
            else if (provider.SubType == "TencentTsec")
            {
                return new TencentTsec(provider.ClientId ?? "", provider.ClientSecret ?? "", provider.AuthEndpoint ?? "",
                    provider.ConfigureUrl ?? "", provider.RegionId ?? "");
            }
            throw new NotImplementedException();
        }
    }
}
