using System.Security.Claims;
using DotNetIdentity.Models;
using DotNetIdentity.Models.Identity;
using DotNetIdentity.Models.ViewModels;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DotNetIdentity.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<AppRole> _roleManager;
        private readonly SignInManager<AppUser> _signInManager;

        public AdminController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager, SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public IActionResult Index() => View();

        public async Task<IActionResult> Users() => View(await _userManager.Users.ToListAsync());

        public async Task<IActionResult> Roles() => View(await _roleManager.Roles.ToListAsync());

        [HttpGet]
        public async Task<IActionResult> UpsertRole(string? id)
        {
            if (id != null)
            {
                var role = await _roleManager.FindByIdAsync(id);
                return View(role.Adapt<UpsertRoleViewModel>());
            }
            return View(new UpsertRoleViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> UpsertRole(UpsertRoleViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var isUpdate = viewModel.Id != null;

                var role = isUpdate ? await _roleManager.FindByIdAsync(viewModel.Id) : new AppRole() { Name = viewModel.Name, CreatedOn = DateTime.Now };

                if (isUpdate)
                {
                    role.Name = viewModel.Name;
                }

                var result = isUpdate ? await _roleManager.UpdateAsync(role) : await _roleManager.CreateAsync(role);
                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
            }
            return View(viewModel);
        }

        [HttpPost]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role != null)
            {
                var result = await _roleManager.DeleteAsync(role);
                if (!result.Succeeded)
                {
                    result.Errors.ToList().ForEach(f => ModelState.AddModelError(string.Empty, f.Description));
                }
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Role not found.");
            }
            return RedirectToAction("Roles");
        }

        public async Task<IActionResult> EditUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return RedirectToAction("Users");
            }
            var viewModel = user.Adapt<EditUserViewModel>();

            var userRoles = await _userManager.GetRolesAsync(user);
            viewModel.Roles = await _roleManager.Roles.Select(s => new AssignRoleViewModel
            {
                RoleId = s.Id,
                RoleName = s.Name,
                IsAssigned = userRoles.Any(a => a == s.Name)
            }).ToListAsync();

            var userClaims = await _userManager.GetClaimsAsync(user);
            var departmentClaim = userClaims.FirstOrDefault(f => f.Type == "Department");
            if (departmentClaim != null)
            {
                viewModel.Department = Enum.Parse<Department>(departmentClaim.Value);
            }

            return View(viewModel);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(viewModel.Id);
                if (user != null)
                {
                    if (user.PhoneNumber != viewModel.PhoneNumber && _userManager.Users.Any(a => a.PhoneNumber == viewModel.PhoneNumber))
                    {
                        ModelState.AddModelError(string.Empty, "Phone number already in use.");
                    }
                    else
                    {
                        user.UserName = viewModel.UserName;
                        user.Email = viewModel.Email;
                        user.PhoneNumber = viewModel.PhoneNumber;
                        user.Gender = viewModel.Gender;

                        var result = await _userManager.UpdateAsync(user);
                        if (result.Succeeded)
                        {
                            // Roles
                            foreach (var item in viewModel.Roles)
                            {
                                if (item.IsAssigned)
                                {
                                    await _userManager.AddToRoleAsync(user, item.RoleName);
                                }
                                else
                                {
                                    await _userManager.RemoveFromRoleAsync(user, item.RoleName);
                                }
                            }

                            // Claims
                            var userClaims = await _userManager.GetClaimsAsync(user);
                            var departmentClaim = userClaims.FirstOrDefault(a => a.Type == "Department");
                            var claimsToAdd = new Claim("Department", Enum.GetName(viewModel.Department)!);
                            if (departmentClaim != null)
                            {
                                await _userManager.ReplaceClaimAsync(user, departmentClaim, claimsToAdd);
                            }
                            else
                            {
                                await _userManager.AddClaimAsync(user, claimsToAdd);
                            }

                            return RedirectToAction("Users");
                        }
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
    }
}