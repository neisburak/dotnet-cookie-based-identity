using System.Text.Encodings.Web;

namespace DotNetIdentity.IdentitySettings
{
    public class TwoFactorAuthenticationService
    {
        private readonly UrlEncoder _urlEncoder;

        public TwoFactorAuthenticationService(UrlEncoder urlEncoder)
        {
            _urlEncoder = urlEncoder;
        }

        public string GenerateQrCodeUri(string email, string authenticatorKey)
        {
            var encodedUrl = _urlEncoder.Encode("www.localhost.com");
            var encodedEmail = _urlEncoder.Encode(email);

            return $"otpauth://totp/{encodedUrl}:{encodedEmail}?secret={authenticatorKey}&issuer={encodedUrl}&digits=6";
        }
    }
}