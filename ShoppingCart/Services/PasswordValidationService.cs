using System.Linq;

namespace CourseWork.Services
{
    public class PasswordValidationService
    {
        public bool ValidatePassword(string password)
        {
            return password.Any(char.IsLetter) && password.Any(char.IsPunctuation);
        }
    }
}