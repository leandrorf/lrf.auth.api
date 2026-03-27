namespace lrf.auth.api.Domain.Entities;

/// <summary>Grupo de usuários; permissões podem ser atribuídas ao grupo inteiro.</summary>
public sealed class Group
{
    public Guid Id { get; set; }

    public required string Name { get; set; }

    public required string NormalizedName { get; set; }

    public ICollection<UserGroup> UserGroups { get; set; } = new List<UserGroup>();

    public ICollection<GroupPermission> GroupPermissions { get; set; } = new List<GroupPermission>();
}
