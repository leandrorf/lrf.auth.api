namespace lrf.auth.api.Domain.Entities;

/// <summary>Nome estável da permissão (ex.: <c>orders.read</c>, <c>admin.users</c>).</summary>
public sealed class Permission
{
    public Guid Id { get; set; }

    public required string Name { get; set; }

    public ICollection<UserPermission> UserPermissions { get; set; } = new List<UserPermission>();

    public ICollection<GroupPermission> GroupPermissions { get; set; } = new List<GroupPermission>();
}
