using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthCenter.Models
{
    [PrimaryKey(nameof(Id))]
    [Index(nameof(Email), IsUnique = true)]
    [Index(nameof(Phone), IsUnique = true)]
    public class User : BaseModelWithoutId
    {
        /// <summary>
        /// 用户名
        /// </summary>
        [Required]
        public string Name { get; set; } = string.Empty;
        /// <summary>
        /// 用户编号/ID
        /// </summary>
        [Required]
        public string Id { get; set; } = string.Empty;
        /// <summary>
        /// 用户头像
        /// </summary>
        public string Avatar { get; set; } = string.Empty;
        /// <summary>
        /// 用户角色
        /// </summary>
        public string[] Roles { get; set; } = [];
        // <summary>
        /// 是否为管理员
        /// </summary>
        public bool IsAdmin { get; set; } = false;
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
        /// <summary>
        /// 偏好MFA类型
        /// </summary>
        public string PreferredMfaType { get; set; } = "";
        /// <summary>
        /// Totp 密钥
        /// </summary>
        public string TotpSecret { get; set; } = "";
        /// <summary>
        /// 是否启用邮件MFA
        /// </summary>
        public bool EnableEmailMfa { get; set; } = false;
        /// <summary>
        /// 是否启用手机MFA
        /// </summary>
        public bool EnablePhoneMfa { get; set; } = false;
        /// <summary>
        /// 是否启用TotpMfa
        /// </summary>
        public bool EnableTotpMfa { get; set; } = false;
        /// <summary>
        /// 救援代码
        /// </summary>
        public string RecoveryCode { get; set; } = "";
        /// <summary>
        /// 登陆错误冻结时间
        /// </summary>
        public DateTime? ForzenLoginUntil { get; set; }
        /// <summary>
        /// 是否禁用
        /// </summary>
        public bool IsForbidden { get; set; } = false;
        public Group? Group { get; set; }
        [NotMapped]
        public int LoginApplication { get; set; } = 0;

        public bool VerifyPassword(string password)
        {
            return BCrypt.Net.BCrypt.Verify(password, Password);
        }
    }
}
