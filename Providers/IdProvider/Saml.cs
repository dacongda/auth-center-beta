using AuthCenter.Models;
using AuthCenter.Utils;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthCenter.Providers.IdProvider
{
    public class Saml(string idpMetadata, UserInfoMap? userInfoMap, string url, IDistributedCache cache) : IIdProvider
    {
        private readonly string _idpMetadata = idpMetadata;
        private readonly UserInfoMap _userInfoMap = userInfoMap ?? new UserInfoMap { };
        private readonly IDistributedCache _cache = cache;

        public async Task<UserInfo> getUserInfo(string samlResponse, string? state, string? tempId)
        {
            var providerInfo = SamlUtil.ParseSamlMetaData(_idpMetadata);
            UserInfo userinfo = SamlUtil.ParseSamlResponseData(samlResponse, providerInfo.Cert, providerInfo.EntityID, url, _userInfoMap, out string requestId);

            var exist = await _cache.GetStringAsync($"Login:SAML:Request{requestId}");
            if (exist == null)
            {
                throw new Exception("Request id not match or request expired");
            }

            return userinfo;
        }
    }
}
