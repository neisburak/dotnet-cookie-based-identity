using System.Security.Claims;
using DotNetIdentity.Helpers;
using DotNetIdentity.IdentitySettings;
using DotNetIdentity.Models.Identity;
using DotNetIdentity.Models.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DotNetIdentity.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly EmailHelper _emailHelper;
        private readonly TwoFactorAuthenticationService _twoFactorAuthService;

        public UserController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorAuthenticationService twoFactorAuthService, EmailHelper emailHelper)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailHelper = emailHelper;
            _twoFactorAuthService = twoFactorAuthService;
        }

        public IActionResult Register() => View();

        [HttpPost]
        public async Task<IActionResult> Register(SignUpViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var user = new AppUser
                {
                    UserName = viewModel.UserName,
                    Email = viewModel.Email,
                    Gender = viewModel.Gender,
                    BirthDay = viewModel.BirthDay,
                    TwoFactorType = Models.TwoFactorType.None,
                    CreatedOn = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user, viewModel.Password);
                if (result.Succeeded)
                {
                    var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action("ConfirmEmail", "User", new
                    {
                        userId = user.Id,
                        token = confirmationToken
                    }, HttpContext.Request.Scheme);

                    await _emailHelper.SendAsync(new()
                    {
                        Subject = "Confirm e-mail",
                        Body = $"Please <a href='{confirmationLink}'>click</a> to confirm your e-mail address.",
                        To = user.Email
                    });

                    return RedirectToAction("Login");
                }
                result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
            }
            return View(viewModel);
        }

        public IActionResult Login(string? returnUrl)
        {
            if (returnUrl != null)
            {
                TempData["ReturnUrl"] = returnUrl;
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(SignInViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(viewModel.Email);
                if (user != null)
                {
                    await _signInManager.SignOutAsync();

                    var result = await _signInManager.PasswordSignInAsync(user, viewModel.Password, viewModel.RememberMe, true);

                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _userManager.SetLockoutEndDateAsync(user, null);

                        var returnUrl = TempData["ReturnUrl"];
                        if (returnUrl != null)
                        {
                            return Redirect(returnUrl.ToString() ?? "/");
                        }
                        return RedirectToAction("Index", "Admin");
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction("TwoFactorLogin", new { ReturnUrl = TempData["ReturnUrl"] });
                    }
                    else if (result.IsLockedOut)
                    {
                        var lockoutEndUtc = await _userManager.GetLockoutEndDateAsync(user);
                        var timeLeft = lockoutEndUtc.Value - DateTime.UtcNow;
                        ModelState.AddModelError(string.Empty, $"This account has been locked out, please try again {timeLeft.Minutes} minutes later.");
                    }
                    else if (result.IsNotAllowed)
                    {
                        ModelState.AddModelError(string.Empty, "You need to confirm your e-mail address.");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid e-mail or password.");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid e-mail or password.");
                }
            }
            return View(viewModel);
        }

        public async Task<IActionResult> TwoFactorLogin(string? returnUrl)
        {
            if (returnUrl != null)
            {
                TempData["ReturnUrl"] = returnUrl;
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            return View(new TwoFactorLoginVieWModel
            {
                TwoFactorType = user.TwoFactorType,
            });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginVieWModel vieWModel)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user.TwoFactorType == Models.TwoFactorType.Authenticator)
            {
                var result = vieWModel.IsRecoveryCode ? await _signInManager.TwoFactorRecoveryCodeSignInAsync(vieWModel.VerificationCode) : await _signInManager.TwoFactorAuthenticatorSignInAsync(vieWModel.VerificationCode, true, false);
                if (result.Succeeded)
                {
                    return Redirect(TempData["ReturnUrl"]?.ToString() ?? "/");
                }
                ModelState.AddModelError(string.Empty, "Verification code is invalid.");
            }
            else if (user.TwoFactorType == Models.TwoFactorType.Email || user.TwoFactorType == Models.TwoFactorType.Sms)
            {
                // Handle verificationCode control flow

                await _signInManager.SignOutAsync();
                await _signInManager.SignInAsync(user, true);

                return Redirect(TempData["ReturnUrl"]?.ToString() ?? "/");
            }

            return View(vieWModel);
        }

        public async Task Logout() => await _signInManager.SignOutAsync();

        public async Task<IActionResult> Profile()
        {
            var me = await _userManager.FindByNameAsync(User.Identity?.Name);
            if (me == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("Index", "Home");
            }
            return View(me.Adapt<UpdateProfileViewModel>());
        }

        [HttpPost]
        public async Task<IActionResult> Profile(UpdateProfileViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var me = await _userManager.FindByNameAsync(User.Identity?.Name);
                if (me != null)
                {
                    if (me.PhoneNumber != viewModel.PhoneNumber && _userManager.Users.Any(a => a.PhoneNumber == viewModel.PhoneNumber))
                    {
                        ModelState.AddModelError(string.Empty, "Phone number already in use.");
                    }
                    else
                    {
                        me.UserName = viewModel.UserName;
                        me.Email = viewModel.Email;
                        me.PhoneNumber = viewModel.PhoneNumber;
                        me.Gender = viewModel.Gender;
                        me.BirthDay = viewModel.BirthDay;

                        var result = await _userManager.UpdateAsync(me);
                        if (result.Succeeded)
                        {
                            await _userManager.UpdateSecurityStampAsync(me);
                            await _signInManager.SignOutAsync();
                            await _signInManager.SignInAsync(me, true);

                            return RedirectToAction("Index", "Admin");
                        }
                        result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                    }
                }
                else
                {
                    await _signInManager.SignOutAsync();
                    return RedirectToAction("Index", "Home");
                }
            }
            return View(viewModel);
        }

        public IActionResult ChangePassword() => View();

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var me = await _userManager.FindByNameAsync(User.Identity?.Name);

                var passwordValid = await _userManager.CheckPasswordAsync(me, viewModel.Password);
                if (passwordValid)
                {
                    var result = await _userManager.ChangePasswordAsync(me, viewModel.Password, viewModel.NewPassword);
                    if (result.Succeeded)
                    {
                        await _userManager.UpdateSecurityStampAsync(me);

                        await _signInManager.SignOutAsync();
                        await _signInManager.SignInAsync(me, true);

                        return RedirectToAction("Index", "Admin");
                    }
                    result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Password is invalid.");
                }
            }

            return View();
        }

        public IActionResult ForgotPassword() => View();

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(viewModel.Email);
                if (user != null)
                {
                    var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var passwordLink = Url.Action("ResetPassword", "User", new
                    {
                        userId = user.Id,
                        token = passwordResetToken
                    }, HttpContext.Request.Scheme);

                    await _emailHelper.SendAsync(new()
                    {
                        Subject = "Reset password",
                        Body = $"Please <a href='{passwordLink}'>click</a> to reset your password.",
                        To = user.Email
                    });

                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User not found.");
                }
            }
            return View(viewModel);
        }

        public IActionResult ResetPassword(string userId, string token)
        {
            if (userId == null || token == null)
            {
                return RedirectToAction("Login", "User");
            }

            return View(new ResetPasswordViewModel
            {
                UserId = userId,
                Token = token
            });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(viewModel.UserId);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, viewModel.Token, viewModel.Password);
                    if (result.Succeeded)
                    {
                        await _userManager.UpdateSecurityStampAsync(user);

                        return RedirectToAction("Login", "User");
                    }
                    else
                    {
                        result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User not found.");
                }
            }
            return View(viewModel);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return RedirectToAction("Login");
                }
            }
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> TwoFactorType()
        {
            var user = await _userManager.FindByNameAsync(User.Identity?.Name);

            return View(new TwoFactorTypeViewModel
            {
                TwoFactorType = user.TwoFactorType
            });
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorType(TwoFactorTypeViewModel viewModel)
        {
            var user = await _userManager.FindByNameAsync(User.Identity?.Name);
            user.TwoFactorType = viewModel.TwoFactorType;
            await _userManager.UpdateAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, user.TwoFactorType != Models.TwoFactorType.None);

            if (viewModel.TwoFactorType == Models.TwoFactorType.Authenticator)
            {
                return RedirectToAction("TwoFactorAuthenticator", "User");
            }
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> TwoFactorAuthenticator()
        {
            var user = await _userManager.FindByNameAsync(User.Identity?.Name);
            if (user.TwoFactorEnabled && user.TwoFactorType == Models.TwoFactorType.Authenticator)
            {
                var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
                if (authenticatorKey == null)
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
                }

                return View(new TwoFactorAuthenticatorViewModel
                {
                    SharedKey = authenticatorKey,
                    AuthenticationUri = _twoFactorAuthService.GenerateQrCodeUri(user.Email, authenticatorKey)
                });
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactorAuthenticator(TwoFactorAuthenticatorViewModel viewModel)
        {
            var user = await _userManager.FindByNameAsync(User.Identity?.Name);
            var verificationCode = viewModel.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (isTokenValid)
            {
                TempData["RecoveryCodes"] = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);
            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult FacebookLogin(string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponse", "User", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);
            return new ChallengeResult("Facebook", properties);
        }

        public IActionResult GoogleLogin(string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponse", "User", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);
            return new ChallengeResult("Google", properties);
        }

        public IActionResult MicrosoftLogin(string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalResponse", "User", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", redirectUrl);
            return new ChallengeResult("Microsoft", properties);
        }

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            var loginInfo = await _signInManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            var externalLoginResult = await _signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, true);
            if (externalLoginResult.Succeeded)
            {
                return Redirect(ReturnUrl);
            }

            var user = new AppUser
            {
                Email = loginInfo.Principal.FindFirst(ClaimTypes.Email)?.Value
            };
            var externalUserId = loginInfo.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (loginInfo.Principal.HasClaim(c => c.Type == ClaimTypes.Name))
            {
                var userName = loginInfo.Principal.FindFirst(ClaimTypes.Name)?.Value;
                if (userName != null)
                {
                    userName = userName.Replace(' ', '-').ToLower() + externalUserId?.Substring(0, 5);
                    user.UserName = userName;
                }
                else
                {
                    user.UserName = user.Email;
                }
            }
            else
            {
                user.UserName = user.Email;
            }

            var existUser = await _userManager.FindByEmailAsync(user.Email);
            if (existUser == null)
            {
                var createResult = await _userManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    var loginResult = await _userManager.AddLoginAsync(user, loginInfo);
                    if (loginResult.Succeeded)
                    {
                        // await SignInManager.SignInAsync(user, true);
                        await _signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, true);
                        return Redirect(ReturnUrl);
                    }
                    else
                    {
                        loginResult.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                    }
                }
                else
                {
                    createResult.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                }
            }
            else
            {
                var loginResult = await _userManager.AddLoginAsync(existUser, loginInfo);
                if (loginResult.Succeeded)
                {
                    // await SignInManager.SignInAsync(user, true);
                    await _signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, true);
                    return Redirect(ReturnUrl);
                }
                else
                {
                    loginResult.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                }
            }

            var errors = ModelState.Values.SelectMany(s => s.Errors).Select(s => s.ErrorMessage).ToList();

            return View("Error", errors);
        }

        public async Task ClaimsPrincipalExample()
        {
            var licenceClaims = new List<Claim>
            {
                new(ClaimTypes.Name, "Burak"),
                new("LicenceType", "B"),
                new("ValidUntil", "2022-09"),
            };

            var passportClaims = new List<Claim>
            {
                new(ClaimTypes.Name, "Burak"),
                new("ValidUntil", "2042-07"),
                new(ClaimTypes.Country, "Turkey")
            };

            var licenceIdentity = new ClaimsIdentity(licenceClaims, "LicenceIdentity");
            var passportIdentity = new ClaimsIdentity(passportClaims, "PassportIdentity");

            var userPrincipal = new ClaimsPrincipal(new[] { licenceIdentity, passportIdentity });

            var authenticationProperties = new AuthenticationProperties { IsPersistent = true };

            await HttpContext.SignInAsync(userPrincipal, authenticationProperties);
        }
    }
}