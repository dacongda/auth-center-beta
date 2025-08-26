namespace AuthCenter.Utils
{
    public class ControllerUtils
    {
        public static string GetFrontUrl(IConfiguration configuration, HttpRequest request)
            => configuration?["FrontEndUrl"] ?? request.Scheme + "://" + request.Host.Value;
    }
}
