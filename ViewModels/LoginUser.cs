namespace AuthCenter.ViewModels
{
    public class LoginUser
    {
        public required string Name { get; set; }
        public required string Password { get; set; }
        public required string GroupName { get; set; }
        public required string LoginMethod { get; set; } = "";
        public string Type { get; set; } = "";
        public string CaptchaId { get; set; } = "";
        public string Code { get; set; } = "";
        public bool IsMfaVerify { get; set; } = false;
    }
    public class LoginResult
    {
        public string? AccessToken { get; set; }
    }

    public class CachedUser
    {
        public string Id { get; set; } = "";
        public int LoginApplication { get; set; }
        public string LoginVia { get; set; } = "";
    }
}
