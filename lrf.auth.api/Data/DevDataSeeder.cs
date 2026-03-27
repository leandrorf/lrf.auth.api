using lrf.auth.api.Domain.Entities;
using lrf.auth.api.Domain.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Data;

/// <summary>Dados apenas para desenvolvimento: permissões por usuário e por grupo.</summary>
public static class DevDataSeeder
{
    public static async Task SeedAsync(AuthDbContext db)
    {
        if (await db.Users.AnyAsync())
            return;

        var permRead = new Permission { Id = Guid.NewGuid(), Name = UserManagementPermissions.Read };
        var permCreate = new Permission { Id = Guid.NewGuid(), Name = UserManagementPermissions.Create };
        var permUpdate = new Permission { Id = Guid.NewGuid(), Name = UserManagementPermissions.Update };
        var permDelete = new Permission { Id = Guid.NewGuid(), Name = UserManagementPermissions.Delete };
        db.Permissions.AddRange(permRead, permCreate, permUpdate, permDelete);

        // Grupo: leitura + cadastro (ex.: equipe que só consulta e inclui usuários).
        var group = new Group
        {
            Id = Guid.NewGuid(),
            Name = "Cadastro de usuários",
            NormalizedName = NormalizeGroupName("Cadastro de usuários"),
        };
        db.Groups.Add(group);
        db.GroupPermissions.Add(new GroupPermission { GroupId = group.Id, PermissionId = permRead.Id });
        db.GroupPermissions.Add(new GroupPermission { GroupId = group.Id, PermissionId = permCreate.Id });

        var hasher = new PasswordHasher<User>();
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "dev@local.dev",
            NormalizedEmail = "DEV@LOCAL.DEV",
            UserName = "dev",
            PasswordHash = "",
            IsActive = true,
            CreatedAtUtc = DateTime.UtcNow,
        };
        user.PasswordHash = hasher.HashPassword(user, "Dev12345!");
        db.Users.Add(user);

        db.UserGroups.Add(new UserGroup { UserId = user.Id, GroupId = group.Id });
        // Direto no usuário: atualização e remoção (além do que já veio do grupo).
        db.UserPermissions.Add(new UserPermission { UserId = user.Id, PermissionId = permUpdate.Id });
        db.UserPermissions.Add(new UserPermission { UserId = user.Id, PermissionId = permDelete.Id });

        await db.SaveChangesAsync();
    }

    private static string NormalizeGroupName(string name) => name.Trim().ToUpperInvariant();
}
