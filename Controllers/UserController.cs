using AuthCenter.Captcha;
using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.Models;
using AuthCenter.Utils;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using System.Linq.Expressions;
using System.Reflection.Metadata;
using System.Text.Json;

namespace AuthCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        private readonly IDistributedCache _cache;
        private readonly AuthCenterDbContext _authCenterDbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConfiguration _configuration;

        public UserController(ILogger<UserController> logger, IDistributedCache cache, AuthCenterDbContext authCenterDbContext, IHttpContextAccessor httpContextAccessor, IConfiguration configuration)
        {
            _logger = logger;
            _cache = cache;
            _authCenterDbContext = authCenterDbContext;
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        [HttpGet("list", Name = "GetUserList")]
        [Authorize(Roles = "admin")]
        public JSONResult List(int page, int pageSize, string? parentChain, string? sortBy, string? sortOrder)
        {

            var countQuery = _authCenterDbContext.User.AsQueryable();
            var query = _authCenterDbContext.User.Include(u => u.Group)
                .Select(user => new { user.Id, user.Number, user.Email, user.Name, user.Phone, user.GroupId, groupName = user.Group.Name });
            if (parentChain != null)
            {
                var groupIds = (from g in _authCenterDbContext.Group where g.ParentChain.StartsWith(parentChain + '/') || g.ParentChain == parentChain select g.Id).ToList();
                countQuery = countQuery.Where(u => groupIds.Contains(u.Id));
                query = query.Where(u => groupIds.Contains(u.GroupId ?? 0));
            }
            var count = countQuery.Count();
            var list = query.Skip((page - 1) * pageSize)
                .Take(pageSize).ToList();
            return JSONResult.ResponseList(list, count);
        }

        [HttpGet(Name = "GetUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Get(int id)
        {
            var user = _authCenterDbContext.User.Where(u => u.Id == id).First();
            if (user == null)
            {
                return JSONResult.ResponseError("无此用户");
            }
            user.Password = "";
            return JSONResult.ResponseOk(user);
        }

        [HttpPost(Name = "AddUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Add(User user)
        {
            _logger.LogInformation(User.Identity?.Name ?? "fail");

            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

            var state = _authCenterDbContext.User.Upsert(user).On(c => c.Number).Run();

            return JSONResult.ResponseOk("成功");
        }

        [HttpPut(Name = "UpdateUser")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Update(User user)
        {
            if (User.IsInRole("user") && User.Identity?.Name != user.Number)
            {
                return JSONResult.ResponseError("无权修改");
            }

            Expression<Func<SetPropertyCalls<User>, SetPropertyCalls<User>>> setPropertyCalls =
                b => b.SetProperty(u => u.Name, user.Name);

            if (user.IsAdmin)
            {
                setPropertyCalls = setPropertyCalls.Append(s =>
                        s.SetProperty(u => u.Number, user.Number)
                        .SetProperty(u => u.Roles, user.Roles)
                        .SetProperty(u => u.Email, user.Email)
                        .SetProperty(u => u.Phone, user.Phone)
                        .SetProperty(u => u.GroupId, user.GroupId)
                        .SetProperty(u => u.IsAdmin, user.IsAdmin));
            }

            _authCenterDbContext.User.Where(u => u.Number == user.Number).ExecuteUpdate(setPropertyCalls);

            return JSONResult.ResponseOk("成功");
        }

        [HttpDelete(Name = "DeleteUser")]
        [Authorize(Roles = "admin")]
        public JSONResult Delete(int id)
        {
            if (id == 1)
            {
                return JSONResult.ResponseError("无法删除主管理，请尝试禁用功能");
            }

            var effected = _authCenterDbContext.User.Where(u => u.Id == id).ExecuteDelete();
            if (effected == 0)
            {
                return JSONResult.ResponseError("删除失败");
            }

            return JSONResult.ResponseOk("成功");
        }

        [HttpGet("myInfo", Name = "GetMyInfo")]
        [Authorize(Roles = "admin,user")]
        public JSONResult GetMyInfo()
        {
            if (User.Identity == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }
            var user = _authCenterDbContext.User.Where(u => u.Number == User.Identity.Name).Include(p => p.Group).FirstOrDefault();
            if (user == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户无效");
            }
            if (user.Group != null)
            {
                var parentGroupNames = user.Group.Name.Split('/');
                var groupChainRoleList = _authCenterDbContext.Group
                    .Where(u => parentGroupNames.Contains(u.Name))
                    .Select(u => u.DefaultRoles).AsNoTracking().ToArray();
                foreach (var groupChainRole in groupChainRoleList)
                {
                    user.Roles = [.. user.Roles.Union(groupChainRole)];
                }
            }

            user.Password = "";
            user.Group = null;
            user.TotpSecret = "";

            return JSONResult.ResponseOk(user);
        }

        [HttpGet("info", Name = "user-info")]
        [Authorize(Roles = "admin,user")]
        public JSONResult Info()
        {
            if (User.Identity == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户信息无效");
            }
            var user = _authCenterDbContext.User.Where(u => u.Number == User.Identity.Name).Include(p => p.Group).FirstOrDefault();
            if (user == null)
            {
                Response.StatusCode = 401;
                return JSONResult.ResponseError("用户无效");
            }

            return JSONResult.ResponseOk(new
            {
                realName = user.Name,
                roles = new List<string>() { user.IsAdmin ? "admin" : "user" },
                userId = user.Number,
                username = user.Name,
                id = user.Id
            });
        }

        [HttpGet("userinfo", Name = "token-userinfo")]
        [Authorize(AuthenticationSchemes = BearerAuthorizationHandler.BearerSchemeName, Roles = "admin,user")]
        public IActionResult UserInfo()
        {
            var user = HttpContext.Items["user"] as User;
            if (user == null)
            {
                Response.Headers.Append("WWW-Authenticate", "Bearer error=\"user not found\", error_description=\"User not found\"");
                return Unauthorized();
            }

            return Json(new
            {
                sub = user.Number,
                name = user.Name,
                email = user.Email,
            });
        }
    }
}
