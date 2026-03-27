namespace lrf.auth.api.Domain.Entities;

public sealed class OAuthClientRedirectUri
{
    public Guid Id { get; set; }

    public required string ClientId { get; set; }

    public OAuthClient Client { get; set; } = null!;

    /// <summary>URI de redirecionamento exatamente como enviado no authorize/token.</summary>
    public required string RedirectUri { get; set; }
}
