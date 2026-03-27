using lrf.auth.api.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Data;

public static class OAuthClientSeeder
{
    public static async Task SeedAsync(AuthDbContext db)
    {
        if (await db.OAuthClients.AnyAsync())
            return;

        var client = new OAuthClient { ClientId = "lrf.auth.web", RequirePkce = true };
        db.OAuthClients.Add(client);
        db.OAuthClientRedirectUris.AddRange(
            new OAuthClientRedirectUri
            {
                Id = Guid.NewGuid(),
                ClientId = client.ClientId,
                RedirectUri = "https://localhost:7167/oauth/callback",
            },
            new OAuthClientRedirectUri
            {
                Id = Guid.NewGuid(),
                ClientId = client.ClientId,
                RedirectUri = "http://localhost:5145/oauth/callback",
            });

        await db.SaveChangesAsync();
    }
}
