using AuthCenter.Models;

namespace AuthCenter.ViewModels.Request
{
    public class ProviderViewModel : Provider
    {
        public string? Destination { get; set; }
    }
}
