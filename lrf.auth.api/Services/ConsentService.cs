using lrf.auth.api.Data;
using lrf.auth.api.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Services;

public sealed class ConsentService : IConsentService
{
    private readonly AuthDbContext _db;

    public ConsentService(AuthDbContext db)
    {
        _db = db;
    }

    public Task<bool> HasConsentAsync(Guid userId, string clientId, string normalizedScope, CancellationToken cancellationToken)
    {
        return _db.UserOAuthConsents.AsNoTracking()
            .AnyAsync(x => x.UserId == userId && x.ClientId == clientId && x.Scope == normalizedScope, cancellationToken);
    }

    public async Task GrantConsentAsync(Guid userId, string clientId, string normalizedScope, CancellationToken cancellationToken)
    {
        var exists = await HasConsentAsync(userId, clientId, normalizedScope, cancellationToken);
        if (exists)
            return;

        _db.UserOAuthConsents.Add(new UserOAuthConsent
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ClientId = clientId,
            Scope = normalizedScope,
            CreatedAtUtc = DateTime.UtcNow,
        });
        await _db.SaveChangesAsync(cancellationToken);
    }

    public string NormalizeScope(string rawScope)
    {
        return string.Join(
            ' ',
            rawScope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal));
    }
}
