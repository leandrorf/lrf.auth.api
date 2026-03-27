namespace lrf.auth.api.Domain.Entities;

public sealed class User
{
    public Guid Id { get; set; }

    public required string Email { get; set; }

    public required string NormalizedEmail { get; set; }

    public required string UserName { get; set; }

    /// <summary>Hash de senha (PasswordHasher).</summary>
    public required string PasswordHash { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; }

    public ICollection<UserGroup> UserGroups { get; set; } = new List<UserGroup>();

    public ICollection<UserPermission> UserPermissions { get; set; } = new List<UserPermission>();
}
