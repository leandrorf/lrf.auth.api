namespace lrf.auth.api.Domain.Entities;

public sealed class OAuthRefreshToken
{
    public Guid Id { get; set; }

    /// <summary>SHA256 do refresh token em hex.</summary>
    public required string TokenHash { get; set; }

    public Guid UserId { get; set; }

    public required string ClientId { get; set; }

    public required string Scope { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    public bool Revoked { get; set; }
}
