using System.ComponentModel.DataAnnotations;

public class User
{
    [Required, MinLength(2, ErrorMessage = "Minimum length is 2")]
    [Display(Name = "Username")]
    public string UserName { get; set; }

    [Required, EmailAddress]
    public string Email { get; set; }

    [DataType(DataType.Password), Required, MinLength(8, ErrorMessage = "Minimum length is 8")]
    public string Password { get; set; }

    public bool HasPasswordRestrictions { get; set; }
}