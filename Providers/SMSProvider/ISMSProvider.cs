using AuthCenter.Models;

namespace AuthCenter.Providers.SMSProvider
{
    public interface ISMSProvider
    {
        public Task<bool> SendSMS(string phone, string[] smsParams);

        public static ISMSProvider GetSMSProvider(Provider provider)
        {
            if (provider.SubType == "Tencent")
            {
                return new TencentSMS(provider.ClientId ?? "", provider.ClientSecret ?? "",
                    provider.ConfigureUrl ?? "", provider.AuthEndpoint ?? "",
                    provider.TokenEndpoint ?? "", provider.RegionId ?? "", provider.SceneId ?? "");
            }
            else if (provider.SubType == "Twilio")
            {
                return new Twilio(provider.ClientId ?? "", provider.ClientSecret ?? "", provider.AuthEndpoint,
                    provider.TokenEndpoint ?? "", provider.RegionId ?? "", provider.SceneId ?? "");
            }

            throw new NotImplementedException();
        }
    }
}
