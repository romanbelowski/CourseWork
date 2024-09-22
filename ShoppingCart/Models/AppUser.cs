using Microsoft.AspNetCore.Identity;

public class AppUser : IdentityUser
{
    public string Occupation { get; set; }
    public bool IsBlocked { get; set; }
    public bool HasPasswordRestrictions { get; set; }
}