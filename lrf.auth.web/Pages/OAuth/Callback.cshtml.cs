using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace lrf.auth.web.Pages.OAuth;

public sealed class CallbackModel : PageModel
{
    private readonly IHttpClientFactory _httpClientFactory;

    public CallbackModel(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public string? ErrorMessage { get; set; }

    public string? RawResponse { get; set; }

    public async Task<IActionResult> OnGetAsync(string? code, string? state, string? error, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(error))
        {
            ErrorMessage = $"Erro do IdP: {error}";
            return Page();
        }

        var expectedState = HttpContext.Session.GetString("oidc_state");
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || expectedState != state)
        {
            ErrorMessage = "Resposta inválida (code/state) ou sessão expirada. Refaça o fluxo em /oauth/start.";
            return Page();
        }

        var verifier = HttpContext.Session.GetString("oidc_verifier");
        if (string.IsNullOrEmpty(verifier))
        {
            ErrorMessage = "Sessão sem code_verifier. Abra novamente /oauth/start.";
            return Page();
        }

        HttpContext.Session.Remove("oidc_state");
        HttpContext.Session.Remove("oidc_verifier");

        var redirectUri = $"{Request.Scheme}://{Request.Host}/oauth/callback";
        var client = _httpClientFactory.CreateClient("AuthApi");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["client_id"] = "lrf.auth.web",
            ["code_verifier"] = verifier,
        };

        using var content = new FormUrlEncodedContent(form);
        using var response = await client.PostAsync("/connect/token", content, cancellationToken);
        RawResponse = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
            ErrorMessage = $"Token endpoint: HTTP {(int)response.StatusCode}";

        return Page();
    }
}
