namespace lrf.auth.api.Services;

public interface IConsentService
{
    Task<bool> HasConsentAsync(Guid userId, string clientId, string normalizedScope, CancellationToken cancellationToken);

    Task GrantConsentAsync(Guid userId, string clientId, string normalizedScope, CancellationToken cancellationToken);

    string NormalizeScope(string rawScope);
}
