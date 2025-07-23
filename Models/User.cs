using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    [Index(nameof(Number), IsUnique = true)]
    public class User : BaseModel
    {
        /// <summary>
        /// 用户名
        /// </summary>
        [Required]
        public required string Name { get; set; }
        /// <summary>
        /// 用户编号/ID
        /// </summary>
        [Required]
        public required string Number { get; set; }
        /// <summary>
        /// 用户角色
        /// </summary>
        public string[] Roles { get; set; } = [];
        /// <summary>
        /// 所属群组
        /// </summary>
        public int? GroupId { get; set; }
        /// <summary>
        /// 电子邮件
        /// </summary>
        public string? Email { get; set; }
        /// <summary>
        /// 是否已认证
        /// </summary>
        public bool EmailVerified { get; set; }
        /// <summary>
        /// 电话
        /// </summary>
        public string? Phone { get; set; }
        /// <summary>
        /// 电话是否已认证
        /// </summary>
        public bool PhoneVerified { get; set; }
        /// <summary>
        /// 密码
        /// </summary>
        public string? Password { get; set; }
        public Group? Group { get; set; }
    }
}
