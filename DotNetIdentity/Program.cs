using DotNetIdentity.Data;
using DotNetIdentity.Helpers;
using DotNetIdentity.IdentitySettings;
using DotNetIdentity.IdentitySettings.Requirements;
using DotNetIdentity.IdentitySettings.Validators;
using DotNetIdentity.Models;
using DotNetIdentity.Models.BusinessModels;
using DotNetIdentity.Models.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddScoped<IClaimsTransformation, ClaimsTransformation>();
builder.Services.AddScoped<IAuthorizationHandler, FreeTrialExpireHandler>();
builder.Services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.AddScoped<EmailHelper>();
builder.Services.AddScoped<TwoFactorAuthenticationService>();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SqlServer"));
});

builder.Services.AddIdentity<AppUser, AppRole>(options =>
{
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;

    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;

    options.SignIn.RequireConfirmedEmail = true;
}).AddUserValidator<UserValidator>()
.AddPasswordValidator<PasswordValidator>()
.AddErrorDescriber<ErrorDescriber>()
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = new PathString("/User/Login");
    options.LogoutPath = new PathString("/User/Logout");
    options.AccessDeniedPath = new PathString("/Home/AccessDenied");

    options.Cookie = new()
    {
        Name = "IdentityCookie",
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        SecurePolicy = CookieSecurePolicy.Always
    };
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
});

builder.Services.AddAuthentication()
.AddFacebook(options =>
{
    options.AppId = builder.Configuration.GetValue<string>("ExternalLoginProviders:Facebook:AppId");
    options.AppSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:Facebook:AppSecret");
    // options.CallbackPath = new PathString("/User/FacebookCallback");
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration.GetValue<string>("ExternalLoginProviders:Google:ClientId");
    options.ClientSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:Google:ClientSecret");
})
.AddMicrosoftAccount(options =>
{
    options.ClientId = builder.Configuration.GetValue<string>("ExternalLoginProviders:Microsoft:ClientId");
    options.ClientSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:Microsoft:ClientSecret");
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HrDepartmentPolicy", policy =>
    {
        policy.RequireClaim("Department", Enum.GetName(Department.HR)!);
    });

    options.AddPolicy("SoftwareDepartmentPolicy", policy =>
    {
        policy.RequireClaim("Department", Enum.GetName(Department.Software)!);
    });

    options.AddPolicy("EmployeePolicy", policy =>
    {
        policy.RequireClaim("Department", Enum.GetNames<Department>());
    });

    options.AddPolicy("FreeTrialPolicy", policy =>
    {
        policy.Requirements.Add(new FreeTrialExpireRequirement());
    });

    options.AddPolicy("AtLeast18Policy", policy =>
    {
        policy.AddRequirements(new MinimumAgeRequirement(18));
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
