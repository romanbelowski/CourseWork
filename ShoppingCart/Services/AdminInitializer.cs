using Microsoft.AspNetCore.Identity;
using CourseWork.Models;

public static class AdminInitializer
{
    public static async Task InitializeAsync(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
    {
        string adminEmail = "admin@example.com";
        string adminPassword = "Admin123!"; // Змініть це на більш безпечний пароль

        if (await roleManager.FindByNameAsync("Admin") == null)
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }

        if (await userManager.FindByNameAsync("ADMIN") == null)
        {
            AppUser admin = new AppUser { UserName = "ADMIN", Email = adminEmail };
            var result = await userManager.CreateAsync(admin, adminPassword);

            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(admin, "Admin");
            }
        }
    }
}