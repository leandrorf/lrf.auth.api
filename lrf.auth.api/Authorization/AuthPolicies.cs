using lrf.auth.api.Domain.Permissions;

namespace lrf.auth.api.Authorization;

/// <summary>Nomes das políticas registradas no ASP.NET Core (uso em <c>[Authorize(Policy = ...)]</c>).</summary>
public static class AuthPolicies
{
    public const string UsersRead = "perm:" + UserManagementPermissions.Read;

    public const string UsersCreate = "perm:" + UserManagementPermissions.Create;

    public const string UsersUpdate = "perm:" + UserManagementPermissions.Update;

    public const string UsersDelete = "perm:" + UserManagementPermissions.Delete;
}
