using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace lrf.auth.web.Pages.OAuth;

public sealed class StartModel : PageModel
{
    private readonly IConfiguration _configuration;

    public StartModel(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public IActionResult OnGet()
    {
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var challengeBytes = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = WebEncoders.Base64UrlEncode(challengeBytes);
        var state = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

        HttpContext.Session.SetString("oidc_verifier", verifier);
        HttpContext.Session.SetString("oidc_state", state);

        var apiBase = _configuration["AuthApi:BaseUrl"]?.TrimEnd('/')
                      ?? throw new InvalidOperationException("AuthApi:BaseUrl");
        var redirectUri = $"{Request.Scheme}://{Request.Host}/oauth/callback";

        var q = new Dictionary<string, string?>
        {
            ["client_id"] = "lrf.auth.web",
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["state"] = state,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };

        var url = QueryHelpers.AddQueryString($"{apiBase}/connect/authorize", q);
        return Redirect(url);
    }
}
