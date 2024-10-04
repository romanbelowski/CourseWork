using CourseWork.Models;
using CourseWork.Models.ViewModels;
using CourseWork.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace CourseWork.Controllers
{
    public class AccountController : Controller
    {
        private UserManager<AppUser> _userManager;
        private SignInManager<AppUser> _signInManager;
        private PasswordValidationService _passwordValidationService;

        public AccountController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, PasswordValidationService passwordValidationService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordValidationService = passwordValidationService;
        }

        public IActionResult Create() => View();

        [HttpPost]
        public async Task<IActionResult> Create(User user)
        {
            if (ModelState.IsValid)
            {
                if (user.UserName.ToUpper() == "ADMIN")
                {
                    ModelState.AddModelError("", "This username is reserved.");
                    Log.Warning("Attempt to create user with reserved username 'ADMIN'");
                    return View(user);
                }

                if (user.HasPasswordRestrictions && !_passwordValidationService.ValidatePassword(user.Password))
                {
                    ModelState.AddModelError("Password", "Password must contain letters and punctuation marks.");
                    Log.Warning("Password creation failed: doesn't meet requirements for user {UserName}", user.UserName);
                    return View(user);
                }

                AppUser newUser = new AppUser
                {
                    UserName = user.UserName,
                    Email = user.Email,
                    HasPasswordRestrictions = user.HasPasswordRestrictions,
                    IsBlocked = false
                };

                IdentityResult result = await _userManager.CreateAsync(newUser, user.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(newUser, isPersistent: false);
                    Log.Information("New user created and signed in: {UserName}", newUser.UserName);
                    return Redirect("/");
                }
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                Log.Warning("User creation failed for {UserName}: {Errors}", user.UserName, string.Join(", ", result.Errors.Select(e => e.Description)));
            }
            return View(user);
        }

        public IActionResult Login(string returnUrl) => View(new LoginViewModel { ReturnUrl = returnUrl });

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginVM)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(loginVM.UserName);
                if (user != null && user.IsBlocked)
                {
                    ModelState.AddModelError("", "This account is blocked. Please contact the administrator.");
                    Log.Warning("Blocked user {UserName} attempted to log in", loginVM.UserName);
                    return View(loginVM);
                }

                Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(loginVM.UserName, loginVM.Password, false, true);
                if (result.Succeeded)
                {
                    Log.Information("User {UserName} logged in successfully", loginVM.UserName);
                    return Redirect(loginVM.ReturnUrl ?? "/");
                }
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account is locked out. Please try again later.");
                    Log.Warning("Locked out user {UserName} attempted to log in", loginVM.UserName);
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password");
                    Log.Warning("Failed login attempt for user {UserName}", loginVM.UserName);
                }
            }
            return View(loginVM);
        }

        public async Task<RedirectResult> Logout(string returnUrl = "/")
        {
            var userName = User.Identity.Name;
            await _signInManager.SignOutAsync();
            Log.Information("User {UserName} logged out", userName);
            return Redirect(returnUrl);
        }

        [Authorize]
        public IActionResult ChangePassword() => View();

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    return NotFound();
                }
                if (user.HasPasswordRestrictions && !_passwordValidationService.ValidatePassword(model.NewPassword))
                {
                    ModelState.AddModelError(string.Empty, "Password must contain letters and punctuation marks.");
                    Log.Warning("Password change failed: doesn't meet requirements for user {UserName}", user.UserName);
                    return View(model);
                }
                var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    foreach (var error in changePasswordResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    Log.Warning("Password change failed for user {UserName}: {Errors}", user.UserName, string.Join(", ", changePasswordResult.Errors.Select(e => e.Description)));
                    return View(model);
                }
                await _signInManager.RefreshSignInAsync(user);
                Log.Information("User {UserName} changed their password", user.UserName);
                return RedirectToAction("Index", "Home");
            }
            return View(model);
        }

        [Authorize(Roles = "Admin")]
        public IActionResult ChangeAdminPassword() => View();

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ChangeAdminPassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync("ADMIN");
                if (user == null)
                {
                    Log.Error("Admin user not found when trying to change password");
                    return NotFound();
                }

                var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    foreach (var error in changePasswordResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    Log.Warning("Admin password change failed: {Errors}", string.Join(", ", changePasswordResult.Errors.Select(e => e.Description)));
                    return View(model);
                }

                await _signInManager.RefreshSignInAsync(user);
                Log.Information("Admin password changed successfully");
                return RedirectToAction("Index", "Home");
            }
            return View(model);
        }
    }
}