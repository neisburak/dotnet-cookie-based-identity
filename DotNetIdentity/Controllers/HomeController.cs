using Microsoft.AspNetCore.Mvc;

namespace DotNetIdentity.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();

    public IActionResult AccessDenied() => View();
}
