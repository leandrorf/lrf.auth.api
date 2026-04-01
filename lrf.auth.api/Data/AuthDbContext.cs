using lrf.auth.api.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Data;

public sealed class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<Group> Groups => Set<Group>();

    public DbSet<Permission> Permissions => Set<Permission>();

    public DbSet<UserGroup> UserGroups => Set<UserGroup>();

    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();

    public DbSet<GroupPermission> GroupPermissions => Set<GroupPermission>();

    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();

    public DbSet<OAuthClientRedirectUri> OAuthClientRedirectUris => Set<OAuthClientRedirectUri>();

    public DbSet<OAuthAuthorizationCode> OAuthAuthorizationCodes => Set<OAuthAuthorizationCode>();

    public DbSet<OAuthRefreshToken> OAuthRefreshTokens => Set<OAuthRefreshToken>();

    public DbSet<UserOAuthConsent> UserOAuthConsents => Set<UserOAuthConsent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(b =>
        {
            b.ToTable("users");
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.NormalizedEmail).IsUnique();
            b.Property(x => x.Email).HasMaxLength(320).IsRequired();
            b.Property(x => x.NormalizedEmail).HasMaxLength(320).IsRequired();
            b.Property(x => x.UserName).HasMaxLength(256).IsRequired();
            b.Property(x => x.PasswordHash).HasMaxLength(500).IsRequired();
        });

        modelBuilder.Entity<Group>(b =>
        {
            b.ToTable("groups");
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.NormalizedName).IsUnique();
            b.Property(x => x.Name).HasMaxLength(120).IsRequired();
            b.Property(x => x.NormalizedName).HasMaxLength(120).IsRequired();
        });

        modelBuilder.Entity<Permission>(b =>
        {
            b.ToTable("permissions");
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.Name).IsUnique();
            b.Property(x => x.Name).HasMaxLength(200).IsRequired();
        });

        modelBuilder.Entity<UserGroup>(b =>
        {
            b.ToTable("user_groups");
            b.HasKey(x => new { x.UserId, x.GroupId });
            b.HasOne(x => x.User)
                .WithMany(x => x.UserGroups)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Group)
                .WithMany(x => x.UserGroups)
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserPermission>(b =>
        {
            b.ToTable("user_permissions");
            b.HasKey(x => new { x.UserId, x.PermissionId });
            b.HasOne(x => x.User)
                .WithMany(x => x.UserPermissions)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Permission)
                .WithMany(x => x.UserPermissions)
                .HasForeignKey(x => x.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<GroupPermission>(b =>
        {
            b.ToTable("group_permissions");
            b.HasKey(x => new { x.GroupId, x.PermissionId });
            b.HasOne(x => x.Group)
                .WithMany(x => x.GroupPermissions)
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Permission)
                .WithMany(x => x.GroupPermissions)
                .HasForeignKey(x => x.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<OAuthClient>(b =>
        {
            b.ToTable("oauth_clients");
            b.HasKey(x => x.ClientId);
            b.Property(x => x.ClientId).HasMaxLength(64).IsRequired();
            b.Property(x => x.DisplayName).HasMaxLength(200).IsRequired();
            b.Property(x => x.AllowedScopes).HasMaxLength(500).IsRequired();
        });

        modelBuilder.Entity<OAuthClientRedirectUri>(b =>
        {
            b.ToTable("oauth_client_redirect_uris");
            b.HasKey(x => x.Id);
            b.HasIndex(x => new { x.ClientId, x.RedirectUri }).IsUnique();
            b.Property(x => x.RedirectUri).HasMaxLength(500).IsRequired();
            b.HasOne(x => x.Client)
                .WithMany(x => x.RedirectUris)
                .HasForeignKey(x => x.ClientId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<OAuthAuthorizationCode>(b =>
        {
            b.ToTable("oauth_authorization_codes");
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.CodeHash).IsUnique();
            b.Property(x => x.CodeHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.ClientId).HasMaxLength(64).IsRequired();
            b.Property(x => x.RedirectUri).HasMaxLength(500).IsRequired();
            b.Property(x => x.CodeChallenge).HasMaxLength(200).IsRequired();
            b.Property(x => x.CodeChallengeMethod).HasMaxLength(10).IsRequired();
            b.Property(x => x.Scope).HasMaxLength(500).IsRequired();
            b.Property(x => x.Nonce).HasMaxLength(500);
        });

        modelBuilder.Entity<OAuthRefreshToken>(b =>
        {
            b.ToTable("oauth_refresh_tokens");
            b.HasKey(x => x.Id);
            b.HasIndex(x => x.TokenHash).IsUnique();
            b.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.ClientId).HasMaxLength(64).IsRequired();
            b.Property(x => x.Scope).HasMaxLength(500).IsRequired();
        });

        modelBuilder.Entity<UserOAuthConsent>(b =>
        {
            b.ToTable("user_oauth_consents");
            b.HasKey(x => x.Id);
            b.HasIndex(x => new { x.UserId, x.ClientId, x.Scope }).IsUnique();
            b.Property(x => x.ClientId).HasMaxLength(64).IsRequired();
            b.Property(x => x.Scope).HasMaxLength(500).IsRequired();
        });
    }
}
