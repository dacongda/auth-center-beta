using AlibabaCloud.SDK.Captcha20230305;
using AlibabaCloud.SDK.Captcha20230305.Models;
using AlibabaCloud.TeaUtil.Models;

namespace AuthCenter.Captcha
{
    public class AliyunCaptcha(string clientId, string clientSercet, string scene) : ICaptchaProvider
    {
        private readonly string _clientId = clientId;
        private readonly string _clientSercet = clientSercet;
        private readonly string _scene = scene;

        public bool VerifyCode(string _, string code)
        {
            var config = new AlibabaCloud.OpenApiClient.Models.Config
            {
                AccessKeyId = _clientId,
                AccessKeySecret = _clientSercet,
                Endpoint = "captcha.cn-shanghai.aliyuncs.com",
            };
            var captchaClient = new Client(config);

            var vertifyReq = new VerifyIntelligentCaptchaRequest
            {
                CaptchaVerifyParam = code,
                SceneId = _scene
            };

            var runtime = new RuntimeOptions();
            try
            {
                var resp = captchaClient.VerifyIntelligentCaptchaWithOptions(vertifyReq, runtime);
                if (resp.Body.Result.VerifyResult == true)
                {
                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
