using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using lrf.auth.web.Contracts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace lrf.auth.web.Pages;

public sealed class LoginModel : PageModel
{
    private readonly IHttpClientFactory _httpClientFactory;

    public LoginModel(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    [BindProperty]
    [Required, EmailAddress]
    public string Email { get; set; } = "";

    [BindProperty]
    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = "";

    public string? ErrorMessage { get; set; }

    public MeResponseDto? Profile { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return Page();

        var client = _httpClientFactory.CreateClient("AuthApi");
        using var loginResponse = await client.PostAsJsonAsync(
            "/api/auth/login",
            new { email = Email, password = Password },
            cancellationToken);

        if (!loginResponse.IsSuccessStatusCode)
        {
            var detail = await TryReadProblemDetailAsync(loginResponse, cancellationToken);
            ErrorMessage = string.IsNullOrWhiteSpace(detail) ? "Não foi possível entrar. Verifique e-mail e senha." : detail;
            return Page();
        }

        var auth = await loginResponse.Content.ReadFromJsonAsync<AuthResponseDto>(
            cancellationToken: cancellationToken);
        if (string.IsNullOrEmpty(auth?.AccessToken))
        {
            ErrorMessage = "Resposta inválida da API de autenticação.";
            return Page();
        }

        using var meRequest = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        meRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.AccessToken);
        using var meResponse = await client.SendAsync(meRequest, cancellationToken);

        if (!meResponse.IsSuccessStatusCode)
        {
            ErrorMessage = "Login ok, mas não foi possível carregar o perfil.";
            return Page();
        }

        Profile = await meResponse.Content.ReadFromJsonAsync<MeResponseDto>(cancellationToken: cancellationToken);
        return Page();
    }

    private static async Task<string?> TryReadProblemDetailAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            if (doc.RootElement.TryGetProperty("detail", out var detail))
                return detail.GetString();
        }
        catch
        {
            // ignored
        }

        return null;
    }
}
