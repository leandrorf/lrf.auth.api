using System.Security.Claims;
using lrf.auth.api.Data;
using lrf.auth.api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Pages.Connect;

[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
public sealed class ConsentModel : PageModel
{
    private readonly AuthDbContext _db;
    private readonly IConsentService _consent;

    public ConsentModel(AuthDbContext db, IConsentService consent)
    {
        _db = db;
        _consent = consent;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string ClientDisplayName { get; private set; } = "";

    public IReadOnlyList<string> Scopes { get; private set; } = Array.Empty<string>();

    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var ok = await LoadAsync(cancellationToken);
        return ok ? Page() : BadRequest(ErrorMessage ?? "Solicitação inválida.");
    }

    public async Task<IActionResult> OnPostAsync(string decision, CancellationToken cancellationToken)
    {
        var ok = await LoadAsync(cancellationToken);
        if (!ok)
            return BadRequest(ErrorMessage ?? "Solicitação inválida.");

        var redirectUri = ReadParam("redirect_uri");
        if (string.IsNullOrEmpty(redirectUri))
            return BadRequest("redirect_uri ausente.");

        if (string.Equals(decision, "deny", StringComparison.Ordinal))
        {
            var denied = QueryHelpers.AddQueryString(
                redirectUri,
                new Dictionary<string, string?>
                {
                    ["error"] = "access_denied",
                    ["state"] = ReadParam("state"),
                });
            return Redirect(denied);
        }

        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (sub is null || !Guid.TryParse(sub, out var userId))
            return Unauthorized();

        await _consent.GrantConsentAsync(
            userId,
            ReadParam("client_id")!,
            _consent.NormalizeScope(string.Join(' ', Scopes)),
            cancellationToken);

        return LocalRedirect(ReturnUrl!);
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        if (!IsSafeReturnUrl(ReturnUrl))
        {
            ErrorMessage = "returnUrl inválida.";
            return false;
        }

        var clientId = ReadParam("client_id");
        var scope = ReadParam("scope");
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(scope))
        {
            ErrorMessage = "Parâmetros obrigatórios ausentes.";
            return false;
        }

        var client = await _db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(x => x.ClientId == clientId, cancellationToken);
        if (client is null)
        {
            ErrorMessage = "Cliente não encontrado.";
            return false;
        }

        ClientDisplayName = string.IsNullOrWhiteSpace(client.DisplayName) ? client.ClientId : client.DisplayName;
        Scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();
        return true;
    }

    private string? ReadParam(string key)
    {
        if (string.IsNullOrEmpty(ReturnUrl))
            return null;

        var queryStart = ReturnUrl.IndexOf('?');
        if (queryStart < 0)
            return null;

        var query = QueryHelpers.ParseQuery(ReturnUrl[(queryStart + 1)..]);
        return query.TryGetValue(key, out var values) ? values.ToString() : null;
    }

    private bool IsSafeReturnUrl(string? returnUrl)
    {
        return !string.IsNullOrEmpty(returnUrl)
               && Url.IsLocalUrl(returnUrl)
               && returnUrl.StartsWith("/connect/authorize", StringComparison.Ordinal);
    }
}
