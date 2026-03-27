using Microsoft.AspNetCore.Authorization;

namespace lrf.auth.api.Authorization;

public static class PermissionAuthorizationExtensions
{
    public const string PermissionClaimType = "permission";

    public static void AddPermissionPolicies(this AuthorizationOptions options, IEnumerable<string> permissionNames)
    {
        foreach (var name in permissionNames)
            options.AddPolicy(PolicyNameFor(name), p => p.RequireClaim(PermissionClaimType, name));
    }

    public static string PolicyNameFor(string permissionName) => "perm:" + permissionName;
}
