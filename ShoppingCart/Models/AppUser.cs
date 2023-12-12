using Microsoft.AspNetCore.Identity;

namespace CourseWork.Models
{
    public class AppUser : IdentityUser
    {
        public string Occupation { get; set; }
    }
}
