using lrf.auth.api.Domain.Entities;

namespace lrf.auth.api.Services;

public interface IJwtTokenService
{
    (string Token, int ExpiresInSeconds) CreateAccessToken(
        User user,
        IReadOnlyCollection<string> groups,
        IReadOnlyCollection<string> permissions,
        string? oauthClientId = null);

    (string Token, int ExpiresInSeconds) CreateIdToken(
        User user,
        string audienceClientId,
        string? nonce,
        IReadOnlyCollection<string> groupNames);
}
