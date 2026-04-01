namespace lrf.auth.api.Domain.Entities;

/// <summary>Cliente OAuth (ex.: SPA). Cliente público usa PKCE e não possui segredo.</summary>
public sealed class OAuthClient
{
    public required string ClientId { get; set; }

    public string DisplayName { get; set; } = "";

    public bool RequirePkce { get; set; } = true;

    /// <summary>Scopes permitidos para o cliente, separados por espaço.</summary>
    public string AllowedScopes { get; set; } = "openid profile";

    public ICollection<OAuthClientRedirectUri> RedirectUris { get; set; } = new List<OAuthClientRedirectUri>();
}
