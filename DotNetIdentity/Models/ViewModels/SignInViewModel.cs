namespace DotNetIdentity.Models.ViewModels
{
    public class SignInViewModel
    {
        public string Email { get; set; } = default!;
        public string Password { get; set; } = default!;
        public bool RememberMe { get; set; } = true;
    }
}