using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace lrf.auth.web.Pages;

/// <summary>Limpa a sessão do site e redireciona para o logoff do IdP (cookie na API).</summary>
public sealed class LogoutModel : PageModel
{
    private readonly IConfiguration _configuration;

    public LogoutModel(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public IActionResult OnGet()
    {
        HttpContext.Session.Clear();

        var apiBase = _configuration["AuthApi:BaseUrl"]?.TrimEnd('/')
                      ?? throw new InvalidOperationException("AuthApi:BaseUrl");
        var home = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/";
        var url = $"{apiBase}/connect/logout?returnUrl={Uri.EscapeDataString(home)}";
        return Redirect(url);
    }
}
