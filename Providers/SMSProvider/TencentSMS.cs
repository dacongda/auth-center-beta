
using System.Runtime.CompilerServices;
using TencentCloud.Common;
using TencentCloud.Sms.V20210111;
using TencentCloud.Sms.V20210111.Models;

namespace AuthCenter.Providers.SMSProvider
{
    public class TencentSMS(string secretId, string secretKey, string appId, 
        string signName, string templateId, string regionId, string senderId) : ISMSProvider
    {
        private readonly Credential _cred = new() { SecretId = secretId, SecretKey = secretKey};
        private readonly string _appId = appId;
        private readonly string _signName = signName;
        private readonly string _templateId = templateId;
        private readonly string _regionId = regionId;
        private readonly string _senderId = senderId;

        public async Task<bool> SendSMS(string phone, string[] smsParams)
        {
            var client = new SmsClient(_cred, _regionId);
            var req = new SendSmsRequest
            {
                SmsSdkAppId = _appId,
                SignName = _signName,
                TemplateId = _templateId,
                PhoneNumberSet = [phone],
                SenderId = _senderId,
                TemplateParamSet = smsParams
            };

            var resp = await client.SendSms(req);

            if (resp.SendStatusSet[0].Code != "Ok")
            {
                return false;
            }

            return true;
        }
    }
}
