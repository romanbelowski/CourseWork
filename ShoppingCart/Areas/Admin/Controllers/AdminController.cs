using CourseWork.Services;
using CourseWork.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CourseWork.Models.ViewModels;

namespace CourseWork.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly PasswordValidationService _passwordValidationService;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(UserManager<AppUser> userManager, PasswordValidationService passwordValidationService, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _passwordValidationService = passwordValidationService;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> UserList()
        {
            var users = await _userManager.Users.ToListAsync();
            return View(users);
        }

        public async Task<IActionResult> EditUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(string id, bool isBlocked, bool hasPasswordRestrictions)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            user.IsBlocked = isBlocked;
            user.HasPasswordRestrictions = hasPasswordRestrictions;
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(UserList));
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(user);
        }

        public async Task<IActionResult> UnblockUser()
        {
            var lockedUsers = await _userManager.Users
                .Where(u => u.LockoutEnd.HasValue && u.LockoutEnd > DateTimeOffset.Now)
                .Select(u => new UserViewModel
                {
                    Id = u.Id,
                    UserName = u.UserName,
                    Email = u.Email,
                    LockoutEnd = u.LockoutEnd
                })
                .ToListAsync();
            return View(lockedUsers);
        }

        [HttpPost]
        public async Task<IActionResult> UnlockUser(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                await _userManager.SetLockoutEndDateAsync(user, null);
                await _userManager.ResetAccessFailedCountAsync(user);
            }
            return RedirectToAction(nameof(UnblockUser));
        }

        public async Task<IActionResult> ChangeAdminPassword()
        {
            var admin = await _userManager.FindByNameAsync("ADMIN");
            if (admin == null)
            {
                return NotFound();
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangeAdminPassword(string currentPassword, string newPassword)
        {
            var admin = await _userManager.FindByNameAsync("ADMIN");
            if (admin == null)
            {
                return NotFound();
            }

            if (!_passwordValidationService.ValidatePassword(newPassword))
            {
                ModelState.AddModelError(string.Empty, "The new password does not meet the required criteria.");
                return View();
            }

            var result = await _userManager.ChangePasswordAsync(admin, currentPassword, newPassword);
            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "Admin password has been changed successfully.";
                return RedirectToAction(nameof(UserList));
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View();
        }

        public async Task<IActionResult> Roles()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (!string.IsNullOrWhiteSpace(roleName))
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));
            }
            return RedirectToAction(nameof(Roles));
        }
    }
}