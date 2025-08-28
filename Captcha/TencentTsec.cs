using Microsoft.AspNetCore.DataProtection;
using NPOI.POIFS.Crypt;
using System.Text.Json;
using TencentCloud.Captcha.V20190722;
using TencentCloud.Captcha.V20190722.Models;
using TencentCloud.Common;

namespace AuthCenter.Captcha
{
    public class TencentTsec(string secretId, string secretKey, 
        string appId, string appSecretId, string regionId) : ICaptchaProvider
    {
        private readonly string _regionId = regionId;
        private readonly string _appId = appId;
        private readonly string _appSecretId = appSecretId;
        private readonly Credential _cred = new() { SecretId = secretId, SecretKey = secretKey };


        public bool VerifyCode(string captchaId, string code, string userIp)
        {

            var client = new CaptchaClient(_cred, _regionId);
            var req = new DescribeCaptchaResultRequest()
            {
                CaptchaType = 9,
                Ticket = code,
                UserIp = userIp,
                Randstr = captchaId,
                CaptchaAppId = Convert.ToUInt64(_appId),
                AppSecretKey = _appSecretId
            };

            var resp = client.DescribeCaptchaResultSync(req);

            return resp.CaptchaCode == 1;
        }
    }
}
