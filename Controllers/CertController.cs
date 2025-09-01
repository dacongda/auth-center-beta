using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace AuthCenter.Controllers

{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "admin")]
    public class CertController(AuthCenterDbContext authCenterDbContext, IConfiguration configuration) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        private readonly IConfiguration _configuration = configuration;

        [HttpGet("list", Name = "GetCertList")]
        public JSONResult List(int? page, int? pageSize)
        {
            if (page != null && pageSize != null)
            {
                var certList = _authCenterDbContext.Cert.Select(cert => new { cert.Id, cert.Name, cert.Type, cert.CryptoAlgorithm, cert.BitSize, cert.CryptoSHASize })
                    .OrderBy(e => e.Id).Skip(((int)page - 1) * (int)pageSize).Take((int)pageSize).ToList();
                var count = _authCenterDbContext.Cert.Count();
                return JSONResult.ResponseList(certList, count);
            }
            var certs = _authCenterDbContext.Cert.Select(cert => new { cert.Id, cert.Name, cert.CryptoAlgorithm });
            return JSONResult.ResponseOk(certs);
        }

        [HttpGet(Name = "GetCert")]
        public JSONResult Get(int id, bool? analyseCert)
        {
            var cert = _authCenterDbContext.Cert.Where(c => c.Id == id).Select(c => new { c.Id, c.Name, c.Type, c.BitSize, c.Certificate, c.CryptoAlgorithm, c.CryptoSHASize }).First();
            if (cert is null)
            {
                return JSONResult.ResponseError("证书不存在");
            }

            if (analyseCert ?? false)
            {
                Cert certFull = new Cert
                {
                    Id = cert.Id,
                    Name = cert.Name,
                    Type = cert.Type,
                    BitSize = cert.BitSize,
                    Certificate = cert.Certificate,
                    CryptoAlgorithm = cert.CryptoAlgorithm,
                    CryptoSHASize = cert.CryptoSHASize
                };

                var c2 = certFull.ToPulibcX509Certificate2();
                certFull.Subject = c2.Subject;
                certFull.Issuer = c2.Issuer;
                certFull.NotAfter = c2.NotAfter;
                certFull.CertFriendlyName = c2.FriendlyName;



                return JSONResult.ResponseOk(certFull);
            }

            return JSONResult.ResponseOk(cert);
        }

        [HttpPost(Name = "AddCert")]
        public JSONResult Add(Cert postCert)
        {
            string defaultDN = _configuration["DefaultDN"] ?? "";
            var cert = CertUtil.CreateNewCert(postCert.Name, postCert.CryptoAlgorithm, postCert.CryptoSHASize, postCert.BitSize, postCert.Type, postCert.DistinguishedName ?? defaultDN, postCert.NotAfter);

            try
            {
                _authCenterDbContext.Add(cert);
                _authCenterDbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                return JSONResult.ResponseError(ex.Message);
            }

            return JSONResult.ResponseOk(cert);
        }

        [HttpPut(Name = "UpdateCert")]
        public JSONResult Update(Cert cert)
        {
            _authCenterDbContext.Cert.Where(u => u.Id == cert.Id).ExecuteUpdate(
                c => c.SetProperty(c => c.Name, cert.Name)
                .SetProperty(c => c.Type, cert.Type)
                );

            return JSONResult.ResponseOk("成功");
        }

        [HttpDelete(Name = "DeleteCert")]
        public JSONResult Delete(int id)
        {
            if (id == 1)
            {
                return JSONResult.ResponseError("无法删除默认证书");
            }

            var effected = _authCenterDbContext.Cert.Where(c => c.Id == id).ExecuteDelete();
            if (effected == 0)
            {
                return JSONResult.ResponseError("删除失败");
            }

            return JSONResult.ResponseOk("成功");
        }
    }
}
