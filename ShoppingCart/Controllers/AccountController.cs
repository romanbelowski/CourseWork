using CourseWork.Models;
using CourseWork.Models.ViewModels;
using CourseWork.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
                    return View(user);
                }

                if (user.HasPasswordRestrictions && !_passwordValidationService.ValidatePassword(user.Password))
                {
                    ModelState.AddModelError("Password", "Password must contain letters and punctuation marks.");
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
                    return Redirect("/");
                }
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
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
                    return View(loginVM);
                }

                Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(loginVM.UserName, loginVM.Password, false, true);
                if (result.Succeeded)
                {
                    return Redirect(loginVM.ReturnUrl ?? "/");
                }
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account is locked out. Please try again later.");
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password");
                }
            }
            return View(loginVM);
        }

        public async Task<RedirectResult> Logout(string returnUrl = "/")
        {
            await _signInManager.SignOutAsync();
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
                    return View(model);
                }
                var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    foreach (var error in changePasswordResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View(model);
                }
                await _signInManager.RefreshSignInAsync(user);
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
                    return NotFound();
                }

                var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    foreach (var error in changePasswordResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View(model);
                }

                await _signInManager.RefreshSignInAsync(user);
                return RedirectToAction("Index", "Home");
            }
            return View(model);
        }
    }
}