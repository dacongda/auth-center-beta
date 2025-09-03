using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.Providers.SMSProvider;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using AuthCenter.ViewModels.Request;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "admin")]
    public class ProviderController(AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        [HttpGet("list", Name = "GetProviderList")]
        public JSONResult List(int? page, int? pageSize)
        {
            if (page is not null && pageSize is not null)
            {
                var providerPageList = _authCenterDbContext.Provider
                    .Select(p => new { p.Id, p.Name, p.DisplayName, p.FaviconUrl, p.Type, p.SubType })
                    .OrderBy(e => e.Id)
                    .Skip((int)((page - 1) * pageSize))
                    .Take((int)pageSize).ToList();
                var count = _authCenterDbContext.Provider.Count();
                return JSONResult.ResponseList(providerPageList, count);
            }

            var providerList = _authCenterDbContext.Provider.Select(p => new { p.Id, p.Name, p.DisplayName, p.FaviconUrl, p.Type, p.SubType }).ToList();
            return JSONResult.ResponseOk(providerList);
        }

        [HttpGet(Name = "GetProvider")]
        public JSONResult Get(int id)
        {
            var provider = _authCenterDbContext.Provider.Find(id);
            if (provider == null)
            {
                return JSONResult.ResponseError("无此提供商");
            }
            return JSONResult.ResponseOk(provider);
        }

        [HttpPost(Name = "AddProvider")]
        public JSONResult Add(Provider provider)
        {

            _authCenterDbContext.Add(provider);
            var ok = _authCenterDbContext.SaveChanges();
            return JSONResult.ResponseOk();
        }

        [HttpPut(Name = "UpadteProvider")]
        public JSONResult Upadte(Provider provider)
        {

            _authCenterDbContext.Update(provider);
            var ok = _authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk();
        }

        [HttpDelete(Name = "DeleteProvider")]
        public JSONResult Delete(int id)
        {
            var effected = _authCenterDbContext.Provider.Where(c => c.Id == id).ExecuteDelete();
            if (effected == 0)
            {
                return JSONResult.ResponseError("删除失败");
            }

            return JSONResult.ResponseOk();
        }

        [HttpPost("testSendEmail", Name = "TestEmailProvider")]
        public JSONResult TestSendEmail(ProviderViewModel provider)
        {
            try
            {
                var body = provider.Body!.Replace("%code%", "123456");
                EmailUtils.SendEmail(provider.ConfigureUrl!, provider.Port!.Value, provider.EnableSSL!.Value, provider.ClientId!, provider.ClientSecret!, provider.Destination!, provider.Subject!, body);
            }
            catch (Exception ex)
            {
                return JSONResult.ResponseError(ex.ToString());
            }

            return JSONResult.ResponseOk();
        }

        [HttpPost("testSendSMS", Name = "TestSMSProvider")]
        public async Task<JSONResult> TestSendSMS(ProviderViewModel provider)
        {
            try
            {
                var smsProvider = ISMSProvider.GetSMSProvider(provider);
                if (!await smsProvider.SendSMS(provider.Destination ?? "", ["123456"]))
                {
                    return JSONResult.ResponseError("发送失败");
                }
            }
            catch (Exception ex)
            {
                return JSONResult.ResponseError(ex.ToString());
            }

            return JSONResult.ResponseOk();
        }
    }
}
