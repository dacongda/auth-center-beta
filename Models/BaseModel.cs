using System.ComponentModel.DataAnnotations;

namespace AuthCenter.Models
{
    public class BaseModel : BaseModelWithoutId
    {
        [Key]
        public int Id { get; set; }
        //public DateTime? DeleteAt { get; set; }
    }

    public class BaseModelWithoutId
    {
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
