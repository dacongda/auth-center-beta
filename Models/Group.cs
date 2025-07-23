using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthCenter.Models
{
    [Index(nameof(Name), IsUnique = true)]
    public class Group : BaseModel
    {
        /// <summary>
        /// 群组名
        /// </summary>
        [Required]
        public required string Name { get; set; }
        /// <summary>
        /// 默认角色
        /// </summary>
        public string[] DefaultRoles { get; set; } = [];
        /// <summary>
        /// 上级Id
        /// </summary>
        public int? ParentId { get; set; }
        /// <summary>
        /// 上级链
        /// </summary>
        public string? ParentChain { get; set; }
        /// <summary>
        /// 根群组Id
        /// </summary>
        public int? TopId { get; set; } = default(int);
        public int? DefaultApplicationId { get; set; }
        public ICollection<User> Users { get; } = [];
        public Application? DefaultApplication { get; set; }
        [NotMapped]
        public List<Group>? Children { get; set; } = [];
        [NotMapped]
        public bool IsLeaf { get; set; }
    }
}
