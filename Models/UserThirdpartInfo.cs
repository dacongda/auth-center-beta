using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    [PrimaryKey(nameof(ProviderName), nameof(UserId))]
    [Index(nameof(ThirdPartId))]
    public class UserThirdpartInfo : BaseModelWithoutId
    {
        public string ProviderName { get; set; } = "";
        public string ThirdPartId { get; set; } = "";
        public string UserId { get; set; } = "";
        public string ThirdPartName { get; set; } = "";
    }
}
