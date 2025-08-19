namespace AuthCenter.Models
{
    public class UploadFile : BaseModel
    {
        public string Filename { get; set; } = String.Empty;
        public string Filepath { get; set; } = String.Empty;
        public string Extension { get; set; } = String.Empty;
        public required int ProviderId { get; set; }
    }
}
