namespace lrf.auth.api.Domain.Entities;

public sealed class UserOAuthConsent
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public required string ClientId { get; set; }

    /// <summary>Scopes consentidos, normalizados e ordenados, separados por espaço.</summary>
    public required string Scope { get; set; }

    public DateTime CreatedAtUtc { get; set; }
}
