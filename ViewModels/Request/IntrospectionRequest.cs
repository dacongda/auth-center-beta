using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels.Request
{
    public class IntrospectionRequest
    {
        [Required]
        public string Token { get; set; } = string.Empty;
        
        public string TokenTypeHint {  get; set; } = string.Empty;
    }
}
