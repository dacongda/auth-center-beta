using AuthCenter.ViewModels.Response;

namespace AuthCenter.ViewModels
{
    public record CasSTStore(string ST, string Service, ServiceResponse CasToken);
}
