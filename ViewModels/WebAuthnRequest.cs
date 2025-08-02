using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels
{
    public class WebAuthnRequest<T>
    {
        [Required]
        public required T RequestValue { get; set; }
        [Required]
        public required string CacheOptionId { get; set; } = string.Empty;
        public string? AuthType { get; set; }
    }
}
