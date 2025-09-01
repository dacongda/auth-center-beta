namespace AuthCenter.Utils
{
    public class ControllerUtils
    {
        public static string GetFrontUrl(IConfiguration configuration, HttpRequest request)
            => string.IsNullOrEmpty(configuration.GetSection("ServerStrings")["FrontEndUrl"]) ? request.Scheme + "://" + request.Host.Value : configuration.GetSection("ServerStrings")["FrontEndUrl"]!;
    }
}
