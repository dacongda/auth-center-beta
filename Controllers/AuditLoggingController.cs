using AuthCenter.Data;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuditLoggingController(AuthCenterDbContext authCenterDbContext) : Controller
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        [HttpGet("getUserSessionList", Name = "GetUserSessionList")]
        [Authorize(Roles = "admin")]
        public async Task<JSONResult> GetUserSessionList(int page, int pageSize)
        {
            var sessionList = await _authCenterDbContext.UserSessions.Where(us => us.LoginType == "login").OrderByDescending(s => s.ExpiredAt).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
            var count = await _authCenterDbContext.Application.CountAsync();
            return JSONResult.ResponseList(sessionList, count);
        }

        [HttpGet("getMySessionList", Name = "GetMySessionList")]
        [Authorize(Roles = "admin,user")]
        public async Task<JSONResult> GetMySessionList(int page, int pageSize)
        {
            var sessionList = await _authCenterDbContext.UserSessions.Where(us => us.LoginType == "login" && us.UserId == User.Identity!.Name).OrderByDescending(s => s.ExpiredAt).ToListAsync();
            return JSONResult.ResponseOk(sessionList);
        }
    }
}
