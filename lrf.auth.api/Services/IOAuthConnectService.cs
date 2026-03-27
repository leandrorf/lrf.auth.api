using lrf.auth.api.Contracts;

namespace lrf.auth.api.Services;

public interface IOAuthConnectService
{
    /// <summary>Se <paramref name="redirectUri"/> for inválido, devolve erro sem URL de redirecionamento.</summary>
    Task<OAuthAuthorizeOutcome> AuthorizeAsync(
        AuthorizeRequestQuery query,
        Guid userId,
        CancellationToken cancellationToken);

    Task<OAuthTokenOutcome> ExchangeCodeAsync(
        TokenFormRequest form,
        CancellationToken cancellationToken);
}

public sealed class OAuthAuthorizeOutcome
{
    public bool HasRedirect { get; init; }

    public string? RedirectLocation { get; init; }

    /// <summary>Quando não há redirect seguro (ex.: <c>redirect_uri</c> inválido).</summary>
    public int? HttpStatus { get; init; }

    public string? HttpBody { get; init; }
}

public sealed class OAuthTokenOutcome
{
    public int StatusCode { get; init; }

    public object? Json { get; init; }
}
