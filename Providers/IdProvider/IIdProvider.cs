using AuthCenter.Models;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Providers.IdProvider
{
    public class UserInfo
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string PreferredName { get; set; } = "";
        public string Email { get; set; } = "";
        public string Phone { get; set; } = "";
    }

    public interface IIdProvider
    {
        public Task<UserInfo> getUserInfo(string code);

        public static IIdProvider GetIdProvider(Provider provider, string redirectUri, IDistributedCache cache)
        {
            if (provider.SubType == "OAuth2")
            {
                return new OAuth2(provider.ClientId ?? "", provider.ClientSecret ?? "", provider.TokenEndpoint ?? "", provider.UserInfoEndpoint ?? "", provider.TokenType ?? "", redirectUri, provider.UserInfoMap!);
            }

            throw new NotImplementedException();
        }
    }
}
