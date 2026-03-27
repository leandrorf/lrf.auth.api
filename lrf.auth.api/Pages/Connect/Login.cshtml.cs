using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using lrf.auth.api.Data;
using lrf.auth.api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Pages.Connect;

[Microsoft.AspNetCore.Authorization.AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly IAuthService _auth;
    private readonly AuthDbContext _db;

    public LoginModel(IAuthService auth, AuthDbContext db)
    {
        _auth = auth;
        _db = db;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    [Required, EmailAddress]
    public string Email { get; set; } = "";

    [BindProperty]
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = "";

    public string? ErrorMessage { get; set; }

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true && IsSafeReturnUrl(ReturnUrl))
            return LocalRedirect(ReturnUrl!);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return Page();

        var (ok, userId) = await _auth.TryCookieSignInAsync(Email, Password, cancellationToken);
        if (!ok || userId is null)
        {
            ErrorMessage = "Credenciais inválidas.";
            return Page();
        }

        var user = await _db.Users.AsNoTracking().FirstAsync(u => u.Id == userId.Value, cancellationToken);
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.UserName),
        };
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
            });

        if (IsSafeReturnUrl(ReturnUrl))
            return LocalRedirect(ReturnUrl!);

        return Redirect("/swagger");
    }

    private bool IsSafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl) || returnUrl.Length > 4096)
            return false;
        if (!Url.IsLocalUrl(returnUrl))
            return false;
        return returnUrl.StartsWith("/connect/authorize", StringComparison.Ordinal);
    }
}
