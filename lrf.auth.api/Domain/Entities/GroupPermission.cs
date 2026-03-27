namespace lrf.auth.api.Domain.Entities;

public sealed class GroupPermission
{
    public Guid GroupId { get; set; }

    public Group Group { get; set; } = null!;

    public Guid PermissionId { get; set; }

    public Permission Permission { get; set; } = null!;
}
