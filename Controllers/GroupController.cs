using AuthCenter.Data;
using AuthCenter.Models;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pipelines.Sockets.Unofficial.Arenas;
using static System.Net.Mime.MediaTypeNames;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthCenter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GroupController(AuthCenterDbContext authCenterDbContext) : ControllerBase
    {
        private readonly AuthCenterDbContext _authCenterDbContext = authCenterDbContext;

        [HttpGet("getGroupTree", Name = "GetGroupTree")]
        [Authorize(Roles = "admin,user")]
        public JSONResult GetGroupTree(int? topGroupId, string? returnType = "tree")
        {
            var query = _authCenterDbContext.Group.AsQueryable();
            if (topGroupId != null)
            {
                query = query.Where(group => group.Id == topGroupId || group.TopId == topGroupId);
            }

            var groupList = query.ToList();

            if (returnType != "tree")
            {
                return JSONResult.ResponseOk(groupList);
            }

            Dictionary<int, List<Group>> groupMap = [];
            List<Group>? topGroups = [];
            foreach (var group in groupList)
            {
                if (group.ParentId == 0)
                {
                    topGroups.Add(group);
                    continue;
                }

                if (!groupMap.ContainsKey((int)group.ParentId))
                {
                    groupMap.Add((int)group.ParentId, []);
                }

                groupMap[(int)group.ParentId].Add(group);
            }

            if (topGroups.Count == 0)
            {
                return JSONResult.ResponseError("群组不存在");
            }

            foreach (var group in groupList)
            {
                if (groupMap.ContainsKey(group.Id))
                {
                    group.Children = groupMap[group.Id];
                }
                else
                {
                    group.Children = null;
                    group.IsLeaf = true;
                }
            }

            return JSONResult.ResponseOk(topGroups);
        }

        [HttpGet("getGroups", Name = "GetGroups")]
        [Authorize(Roles = "admin")]
        public JSONResult GetGroups(int page, int pageSize, string? sortBy, string? sortOrder)
        {
            var parentCount = _authCenterDbContext.Group
                .Where(group => group.ParentId == 0)
                .Count();
            var parentGroups = _authCenterDbContext.Group
                .Where(group => group.ParentId == 0)
                .Skip((page - 1) * parentCount).
                Take(pageSize)
                .ToList();
            var parentIds = parentGroups.Select(g => g.Id).ToList();
            var subGroups = _authCenterDbContext.Group.Where(group => parentIds.Contains(group.TopId ?? 0)).ToList();

            parentGroups.AddRange(subGroups);

            return JSONResult.ResponseList(parentGroups, parentCount);
        }

        [HttpGet("refreshGroupChain", Name = "RefreshGroupChain")]
        [Authorize(Roles = "admin")]
        public JSONResult RefreshChain()
        {
            var groupList = _authCenterDbContext.Group.ToList();
            Dictionary<int, List<Group>> groupChildMap = [];
            Dictionary<int, Group> groupMap = [];
            List<Group>? topGroups = [];
            Queue<Group> groupQueue = new();
            foreach (var group in groupList)
            {
                groupMap.Add(group.Id, group);

                if (group.ParentId == 0)
                {
                    topGroups.Add(group);
                    groupQueue.Enqueue(group);
                    continue;
                }

                if (!groupChildMap.ContainsKey((int)group.ParentId))
                {
                    groupChildMap.Add((int)group.ParentId, []);
                }

                groupChildMap[(int)group.ParentId].Add(group);
            }

            if (topGroups.Count == 0)
            {
                return JSONResult.ResponseError("群组不存在");
            }

            foreach (var group in groupList)
            {
                if (groupChildMap.ContainsKey(group.Id))
                {
                    group.Children = groupChildMap[group.Id];
                }
                else
                {
                    group.Children = null;
                    group.IsLeaf = true;
                }
            }

            while (groupQueue.Count != 0)
            {
                var curGroup = groupQueue.Dequeue();
                if (curGroup.ParentId == 0)
                {
                    curGroup.ParentChain = curGroup.Name;
                }
                else
                {
                    var parentGroup = groupMap[(int)curGroup.ParentId];
                    curGroup.ParentChain = parentGroup.ParentChain + $"/{curGroup.Name}";
                }

                if (curGroup.Children is null)
                {
                    continue;
                }

                foreach (var child in curGroup.Children)
                {
                    groupQueue.Enqueue(child);
                }
            }

            _authCenterDbContext.Group.UpdateRange(groupList);
            _authCenterDbContext.SaveChanges();

            return JSONResult.ResponseOk("成功执行");
        }

        [HttpGet("getGroupWithApplication", Name = "GetGroupWithApplication")]
        [AllowAnonymous]
        public JSONResult GetGroupWithApplication(string groupName, string? clientId)
        {
            if (clientId != null)
            {
                var splitedClient = clientId.Split("-", 2);
                groupName = splitedClient.Length == 2 ? splitedClient[1] : groupName;
                clientId = splitedClient[0];
            }

            var group = _authCenterDbContext.Group.Where(g => g.Name == groupName).AsNoTracking().FirstOrDefault();
            if (group == null)
            {
                return JSONResult.ResponseError("群组不存在");
            }

            if (clientId != null)
            {
                var application = _authCenterDbContext.Application.Where(app => app.ClientId == clientId)
                    .Select(app => new Models.Application { Id = app.Id, Name = app.Name, ProviderItems = app.ProviderItems }).AsNoTracking().FirstOrDefault();
                group.DefaultApplication = application;
            } else
            {
                var application = _authCenterDbContext.Application.Where(app => app.Id == group.DefaultApplicationId)
                    .Select(app => new Models.Application { Id = app.Id, Name = app.Name, ProviderItems = app.ProviderItems }).AsNoTracking().FirstOrDefault();
                group.DefaultApplication = application;
            }

            if (group.DefaultApplication == null)
            {
                return JSONResult.ResponseError("应用不存在");
            }

            var app = group.DefaultApplication;
            var appProviderItems = (from pItem in app.ProviderItems where pItem.Type == "Captcha" || pItem.Type == "Auth" select pItem.ProviderId).ToList();
            if (appProviderItems.Any())
            {
                group.DefaultApplication.Providers = [.. _authCenterDbContext.Provider.Where(p => appProviderItems.Contains(p.Id)).Select(p => new Provider{
                    Name = p.Name,
                    DisplayName = p.DisplayName,
                    Type = p.Type,
                    SubType = p.SubType,
                    FaviconUrl = p.FaviconUrl,
                    ClientId = p.ClientId,
                    AuthEndpoint = p.AuthEndpoint,
                    Scopes = p.Scopes
                })];
            }

            return JSONResult.ResponseOk(group);
        }

        [HttpGet(Name = "GetGroup")]
        [Authorize(Roles = "admin")]
        public JSONResult Get(int id)
        {
            var group = _authCenterDbContext.Group.Find(id);
            if (group == null)
            {
                return JSONResult.ResponseError("群组不存在");
            }
            return JSONResult.ResponseOk(group);
        }


        [HttpPost(Name = "AddGroup")]
        [Authorize(Roles = "admin")]
        public JSONResult Post(Group group)
        {
            if (group.ParentId != 0)
            {
                var parent = _authCenterDbContext.Group.Find(group.ParentId);
                if (parent == null)
                {
                    return JSONResult.ResponseError("上级群组不存在");
                }

                group.TopId = parent.TopId == 0 ? parent.Id : parent.ParentId;
                group.ParentChain = parent.ParentChain + $"/{group.Name}";
            }
            else
            {
                group.ParentChain = group.Name;
            }
            _authCenterDbContext.Add(group);
            _authCenterDbContext.SaveChanges();
            return JSONResult.ResponseOk("成功");
        }

        [HttpPut(Name = "UpdateGroup")]
        [Authorize(Roles = "admin")]
        public JSONResult Put(Group group)
        {
            var oldGroup = _authCenterDbContext.Group.AsNoTracking().First(g => g.Id == group.Id);
            if (oldGroup is null)
            {
                return JSONResult.ResponseError("原群组不存在");
            }

            group.ParentChain = oldGroup.ParentChain;

            if (oldGroup.Name != group.Name)
            {
                group.ParentChain = group.ParentChain?.Replace(oldGroup.Name, group.Name);
            }

            if (oldGroup.ParentId != group.ParentId)
            {
                var parentNew = _authCenterDbContext.Group.Find(group.ParentId);
                if (parentNew == null)
                {
                    return JSONResult.ResponseError("新上级群组不存在");
                }

                group.ParentChain = parentNew.ParentChain + $"/{group.Name}";
                group.TopId = (parentNew.TopId == null || parentNew.TopId == 0) ? parentNew.Id : parentNew.TopId;
            } else
            {
                group.ParentChain = oldGroup.ParentChain;
                group.TopId = oldGroup.TopId;
            }

                var updated = _authCenterDbContext.Group
                        .Where(g => g.Id == group.Id).ExecuteUpdate(s =>
                    s.SetProperty(g => g.Name, group.Name)
                    .SetProperty(g => g.DefaultRoles, group.DefaultRoles)
                    .SetProperty(g => g.DefaultApplicationId, group.DefaultApplicationId)
                    .SetProperty(g => g.ParentId, group.ParentId)
                    .SetProperty(g => g.TopId, group.TopId)
                    .SetProperty(g => g.ParentChain, group.ParentChain)
                    .SetProperty(g => g.DisplayName, group.DisplayName));

            if (updated <= 0)
            {
                return JSONResult.ResponseError("更新失败");
            }

            if (oldGroup.Name != group.Name || oldGroup.ParentId != group.ParentId)
            {
                var childList = _authCenterDbContext.Group.Where(g => g.ParentChain.StartsWith(oldGroup.ParentChain + '/')).ToList();
                if (childList.Count != 0)
                {
                    foreach (var child in childList)
                    {
                        child.ParentChain = group.ParentChain + child.ParentChain.Substring(child.ParentChain.IndexOf(oldGroup.ParentChain) + oldGroup.ParentChain.Length);
                    }

                    _authCenterDbContext.UpdateRange(childList);
                    _authCenterDbContext.SaveChanges();
                }
            }

            return JSONResult.ResponseOk("成功");
        }

        [HttpDelete(Name = "DeleteGroup")]
        [Authorize(Roles = "admin")]
        public JSONResult Delete(int id)
        {
            if (_authCenterDbContext.Group.Where(g => g.ParentId == id).FirstOrDefault() != null)
            {
                return JSONResult.ResponseError("请先处理子群组");
            }

            if (_authCenterDbContext.User.Where(u => u.GroupId == id).FirstOrDefault() != null)
            {
                return JSONResult.ResponseError("请先处理归属用户");
            }

            _authCenterDbContext.Group.Remove(new() { Id = id, Name = "", DisplayName = "", DefaultRoles = [] });
            var deleted = _authCenterDbContext.SaveChanges();
            if (deleted <= 0)
            {
                return JSONResult.ResponseError("删除失败");
            }
            return JSONResult.ResponseOk("成功");
        }
    }
}
