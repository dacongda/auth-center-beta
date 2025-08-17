using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    [Index(nameof(UserId))]
    public class UserSession
    {
        [Key]
        public string SessionId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string LoginType {  get; set; } = string.Empty;
        public string LoginMethod { get; set; } = string.Empty;
        public string LoginToken {  get; set; } = string.Empty;
        public string LoginApplication {  get; set; } = string.Empty;
        public string LoginVia { get; set; } = string.Empty;
        public string LoginIp { get; set; } = string.Empty;
        public DateTime ExpiredAt { get; set; } = DateTime.MinValue;
    }
}
