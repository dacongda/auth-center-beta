using System.Text.Json;
using Twilio.Clients;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace AuthCenter.Providers.SMSProvider
{
    public class Twilio(string accountSid, string authToken, string sender, string templateId, string regionId, string edge) : ISMSProvider
    {
        private readonly TwilioRestClient _client = new(accountSid, authToken, accountSid, regionId, edge: edge);
        private readonly string _templateId = templateId;

        public async Task<bool> SendSMS(string phone, string[] smsParams)
        {
            var phoneNumber = new PhoneNumber(phone);
            var paramDict = new Dictionary<string, string>();
            for (var i = 0; i < smsParams.Length; i++)
            {
                paramDict[(i + 1).ToString()] = smsParams[i];
            }
            string paramJsonStr = JsonSerializer.Serialize(paramDict);
            _ = await MessageResource.CreateAsync(phoneNumber, from: sender, contentSid: _templateId, contentVariables: paramJsonStr, client: _client);

            return true;
        }
    }
}
