using lrf.auth.api.Contracts;

namespace lrf.auth.api.Services;

public interface IAuthService
{
    Task<(bool Ok, string? Error)> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken);

    Task<(bool Ok, AuthResponse? Body, string? Error)> LoginAsync(LoginRequest request, CancellationToken cancellationToken);

    Task<MeResponse?> GetMeAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>Sessão do IdP (cookie) após validar e-mail e senha.</summary>
    Task<(bool Ok, Guid? UserId)> TryCookieSignInAsync(
        string email,
        string password,
        CancellationToken cancellationToken);
}
