using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "admin")]
    public class ApplicationController(AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;
        [HttpGet("list", Name = "ListApplication")]
        public JSONResult List(int page, int pageSize)
        {
            var appList = _authCenterDbContext.Application.Select(app => new { app.Id, app.Name, app.ClientId }).Skip((page - 1) * pageSize).Take(pageSize).ToList();
            var count = _authCenterDbContext.Application.Count();
            return JSONResult.ResponseList(appList, count);
        }

        [HttpGet(Name = "GetApplication")]
        public JSONResult Get(int id)
        {
            var app = _authCenterDbContext.Application.Where(app => app.Id == id).First();
            if (app == null)
            {
                return JSONResult.ResponseError("无此应用");
            }

            return JSONResult.ResponseOk(app);
        }

        [HttpPost(Name = "AddApp")]
        public JSONResult Add(Application application)
        {

            _authCenterDbContext.Add(application);
            var ok = _authCenterDbContext.SaveChanges();
            return JSONResult.ResponseOk();
        }

        [HttpPut(Name = "UpadteApp")]
        public JSONResult Upadte(Application application)
        {

            _authCenterDbContext.Update(application);
            var ok = _authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk();
        }

        [HttpDelete(Name = "DeleteApp")]
        public JSONResult Delete(int id)
        {
            _authCenterDbContext.Remove(new Application { Id = id });
            var ok = _authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk();
        }
    }
}
