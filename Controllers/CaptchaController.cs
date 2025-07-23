using AuthCenter.Data;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace AuthCenter.Controllers
{
    public class CaptchaController(AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        public JSONResult GetCaptcha(int applicationId)
        {
            var app = _authCenterDbContext.Application.Find(applicationId);
            if (app == null)
            {
                return JSONResult.ResponseError("应用不存在");
            }

            var (code, res) = Utils.CaptchaUtils.GenerateCodeStr(4, "Calculate");

            return JSONResult.ResponseOk();
        }
    }
}
