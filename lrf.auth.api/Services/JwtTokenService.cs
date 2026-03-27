using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using lrf.auth.api.Domain.Entities;
using lrf.auth.api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace lrf.auth.api.Services;

public sealed class JwtTokenService : IJwtTokenService
{
    private readonly JwtOptions _options;
    private readonly SigningCredentials _signingCredentials;
    private readonly JwtSecurityTokenHandler _handler = new();

    public JwtTokenService(IOptions<JwtOptions> options)
    {
        _options = options.Value;
        if (string.IsNullOrWhiteSpace(_options.SigningKey) || _options.SigningKey.Length < 32)
            throw new InvalidOperationException("Jwt:SigningKey deve ter pelo menos 32 caracteres.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    public (string Token, int ExpiresInSeconds) CreateAccessToken(
        User user,
        IReadOnlyCollection<string> groups,
        IReadOnlyCollection<string> permissions,
        string? oauthClientId = null)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(Math.Max(1, _options.AccessTokenMinutes));
        var expiresIn = (int)(expires - now).TotalSeconds;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        if (!string.IsNullOrEmpty(oauthClientId))
            claims.Add(new Claim("client_id", oauthClientId));

        foreach (var g in groups.OrderBy(x => x, StringComparer.Ordinal))
            claims.Add(new Claim("group", g));

        foreach (var p in permissions.OrderBy(x => x, StringComparer.Ordinal))
            claims.Add(new Claim("permission", p));

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: _signingCredentials);

        return (_handler.WriteToken(token), expiresIn);
    }

    public (string Token, int ExpiresInSeconds) CreateIdToken(
        User user,
        string audienceClientId,
        string? nonce,
        IReadOnlyCollection<string> groupNames)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(10);
        var expiresIn = (int)(expires - now).TotalSeconds;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Name, user.UserName),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        if (!string.IsNullOrEmpty(nonce))
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

        foreach (var g in groupNames.OrderBy(x => x, StringComparer.Ordinal))
            claims.Add(new Claim("groups", g));

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: audienceClientId,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: _signingCredentials);

        return (_handler.WriteToken(token), expiresIn);
    }
}
