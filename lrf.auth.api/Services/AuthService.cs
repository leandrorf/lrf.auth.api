using lrf.auth.api.Contracts;
using lrf.auth.api.Data;
using lrf.auth.api.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Services;

public sealed class AuthService : IAuthService
{
    private readonly AuthDbContext _db;
    private readonly IJwtTokenService _jwt;
    private readonly PasswordHasher<User> _passwordHasher = new();

    public AuthService(AuthDbContext db, IJwtTokenService jwt)
    {
        _db = db;
        _jwt = jwt;
    }

    public async Task<(bool Ok, string? Error)> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);
        var exists = await _db.Users.AnyAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken);
        if (exists)
            return (false, "E-mail já cadastrado.");

        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = request.Email.Trim(),
            NormalizedEmail = normalizedEmail,
            UserName = request.UserName.Trim(),
            PasswordHash = "",
            IsActive = true,
            CreatedAtUtc = DateTime.UtcNow,
        };
        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);

        _db.Users.Add(user);
        await _db.SaveChangesAsync(cancellationToken);
        return (true, null);
    }

    public async Task<(bool Ok, AuthResponse? Body, string? Error)> LoginAsync(LoginRequest request, CancellationToken cancellationToken)
    {
        var user = await LoadActiveUserIfPasswordValidAsync(request.Email, request.Password, cancellationToken);
        if (user is null)
            return (false, null, "Credenciais inválidas.");

        var groupsAndPerms = await LoadGroupsAndPermissionsAsync(user.Id, cancellationToken);
        var (token, expiresIn) = _jwt.CreateAccessToken(user, groupsAndPerms.Groups, groupsAndPerms.Permissions);

        return (true, new AuthResponse
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresInSeconds = expiresIn,
        }, null);
    }

    public async Task<(bool Ok, Guid? UserId)> TryCookieSignInAsync(
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var user = await LoadActiveUserIfPasswordValidAsync(email, password, cancellationToken);
        return user is null ? (false, null) : (true, user.Id);
    }

    private async Task<User?> LoadActiveUserIfPasswordValidAsync(
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(email);
        var user = await _db.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken);
        if (user is null || !user.IsActive)
            return null;

        return _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) == PasswordVerificationResult.Failed
            ? null
            : user;
    }

    public async Task<MeResponse?> GetMeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId && u.IsActive, cancellationToken);
        if (user is null)
            return null;

        var data = await LoadGroupsAndPermissionsAsync(userId, cancellationToken);
        return new MeResponse
        {
            UserId = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            Groups = data.Groups,
            Permissions = data.Permissions,
        };
    }

    private async Task<(List<string> Groups, List<string> Permissions)> LoadGroupsAndPermissionsAsync(Guid userId, CancellationToken cancellationToken)
    {
        var directPermIds = await _db.UserPermissions
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .Select(x => x.PermissionId)
            .ToListAsync(cancellationToken);

        var groupIds = await _db.UserGroups
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .Select(x => x.GroupId)
            .ToListAsync(cancellationToken);

        var groupNames = await _db.Groups
            .AsNoTracking()
            .Where(g => groupIds.Contains(g.Id))
            .OrderBy(g => g.Name)
            .Select(g => g.Name)
            .ToListAsync(cancellationToken);

        var groupPermIds = await _db.GroupPermissions
            .AsNoTracking()
            .Where(x => groupIds.Contains(x.GroupId))
            .Select(x => x.PermissionId)
            .Distinct()
            .ToListAsync(cancellationToken);

        var allPermIds = directPermIds.Concat(groupPermIds).Distinct().ToList();

        var permissionNames = await _db.Permissions
            .AsNoTracking()
            .Where(p => allPermIds.Contains(p.Id))
            .OrderBy(p => p.Name)
            .Select(p => p.Name)
            .ToListAsync(cancellationToken);

        return (groupNames, permissionNames);
    }

    private static string NormalizeEmail(string email) => email.Trim().ToUpperInvariant();
}
