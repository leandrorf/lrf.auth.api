namespace lrf.auth.api.Domain.Entities;

public sealed class OAuthAuthorizationCode
{
    public Guid Id { get; set; }

    /// <summary>SHA256 do código em hex (minúsculas), para lookup sem guardar código em claro.</summary>
    public required string CodeHash { get; set; }

    public Guid UserId { get; set; }

    public required string ClientId { get; set; }

    public required string RedirectUri { get; set; }

    public required string CodeChallenge { get; set; }

    public required string CodeChallengeMethod { get; set; }

    public required string Scope { get; set; }

    public string? Nonce { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    public bool Consumed { get; set; }
}
