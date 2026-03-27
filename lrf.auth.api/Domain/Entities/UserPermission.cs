namespace lrf.auth.api.Domain.Entities;

public sealed class UserPermission
{
    public Guid UserId { get; set; }

    public User User { get; set; } = null!;

    public Guid PermissionId { get; set; }

    public Permission Permission { get; set; } = null!;
}
