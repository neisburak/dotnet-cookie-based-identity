using Microsoft.AspNetCore.Identity;

namespace DotNetIdentity.Models.Identity
{
    public class AppUser : IdentityUser
    {
        public TwoFactorType TwoFactorType { get; set; }
        public DateTime BirthDay { get; set; }
        public Gender Gender { get; set; }
        public DateTime CreatedOn { get; set; }
    }
}