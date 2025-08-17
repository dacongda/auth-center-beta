using System.ComponentModel.DataAnnotations;

namespace AuthCenter.ViewModels
{
    public class IntrospectionRequest
    {
        [Required]
        public string Token { get; set; } = string.Empty;
        
        public string TokenTypeHint {  get; set; } = string.Empty;
    }
}
