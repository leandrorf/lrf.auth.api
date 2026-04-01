using lrf.auth.api.Contracts;
using lrf.auth.api.Data;
using lrf.auth.api.Domain.Entities;
using lrf.auth.api.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace lrf.auth.api.Services;

public sealed class OAuthConnectService : IOAuthConnectService
{
    private readonly AuthDbContext _db;
    private readonly IJwtTokenService _jwt;
    private readonly IAuthService _auth;
    private readonly IOidcSigningKeyService _signingKeys;
    private readonly IConsentService _consent;

    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(7);

    public OAuthConnectService(
        AuthDbContext db,
        IJwtTokenService jwt,
        IAuthService auth,
        IOidcSigningKeyService signingKeys,
        IConsentService consent)
    {
        _db = db;
        _jwt = jwt;
        _auth = auth;
        _signingKeys = signingKeys;
        _consent = consent;
    }

    public async Task<OAuthAuthorizeOutcome> AuthorizeAsync(
        AuthorizeRequestQuery q,
        Guid userId,
        CancellationToken cancellationToken)
    {
        string AppendQuery(string uri, params (string key, string? value)[] pars)
        {
            var s = uri;
            foreach (var (key, value) in pars)
            {
                if (value != null)
                    s = QueryHelpers.AddQueryString(s, key, value);
            }

            return s;
        }

        string ErrRedirect(string error, string? desc = null)
        {
            if (string.IsNullOrEmpty(q.redirect_uri))
                return "";
            try
            {
                var u = AppendQuery(q.redirect_uri, ("error", error), ("error_description", desc), ("state", q.state))!;
                return u;
            }
            catch
            {
                return "";
            }
        }

        if (string.IsNullOrWhiteSpace(q.client_id)
            || string.IsNullOrWhiteSpace(q.redirect_uri)
            || string.IsNullOrWhiteSpace(q.response_type)
            || string.IsNullOrWhiteSpace(q.code_challenge)
            || string.IsNullOrWhiteSpace(q.code_challenge_method))
        {
            var loc = ErrRedirect("invalid_request", "Parâmetro obrigatório ausente.");
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return new OAuthAuthorizeOutcome
            {
                HttpStatus = StatusCodes.Status400BadRequest,
                HttpBody = "invalid_request",
            };
        }

        if (!string.Equals(q.response_type, "code", StringComparison.Ordinal))
        {
            var loc = ErrRedirect("unsupported_response_type", null);
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        if (!string.Equals(q.code_challenge_method, "S256", StringComparison.Ordinal))
        {
            var loc = ErrRedirect("invalid_request", "code_challenge_method deve ser S256.");
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        var client = await _db.OAuthClients
            .AsNoTracking()
            .Include(c => c.RedirectUris)
            .FirstOrDefaultAsync(c => c.ClientId == q.client_id, cancellationToken);
        if (client is null)
        {
            var loc = ErrRedirect("unauthorized_client", null);
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        if (client.RequirePkce && string.IsNullOrWhiteSpace(q.code_challenge))
        {
            var loc = ErrRedirect("invalid_request", "PKCE obrigatório.");
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        var redirectOk = client.RedirectUris.Any(r => string.Equals(r.RedirectUri, q.redirect_uri, StringComparison.Ordinal));
        if (!redirectOk)
        {
            return new OAuthAuthorizeOutcome
            {
                HttpStatus = StatusCodes.Status400BadRequest,
                HttpBody = "redirect_uri inválido para este client_id.",
            };
        }

        var scope = (q.scope ?? "").Trim();
        if (string.IsNullOrEmpty(scope))
        {
            var loc = ErrRedirect("invalid_scope", "scope é obrigatório.");
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var allowedScopes = client.AllowedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (requestedScopes.Except(allowedScopes, StringComparer.Ordinal).Any())
        {
            var loc = ErrRedirect("invalid_scope", "scope não permitido para o cliente.");
            if (!string.IsNullOrEmpty(loc))
                return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = loc };
            return BadOutcome();
        }

        var normalizedScope = _consent.NormalizeScope(scope);
        var hasConsent = await _consent.HasConsentAsync(userId, client.ClientId, normalizedScope, cancellationToken);
        if (!hasConsent)
        {
            var returnUrl = QueryHelpers.AddQueryString(
                "/connect/authorize",
                new Dictionary<string, string?>
                {
                    ["client_id"] = q.client_id,
                    ["redirect_uri"] = q.redirect_uri,
                    ["response_type"] = q.response_type,
                    ["scope"] = q.scope,
                    ["state"] = q.state,
                    ["code_challenge"] = q.code_challenge,
                    ["code_challenge_method"] = q.code_challenge_method,
                    ["nonce"] = q.nonce,
                });
            return new OAuthAuthorizeOutcome
            {
                HasRedirect = true,
                RedirectLocation = QueryHelpers.AddQueryString("/connect/consent", "returnUrl", returnUrl),
            };
        }

        var rawCode = PkceVerifier.CreateAuthorizationCodeRaw();
        var codeHash = PkceVerifier.HashAuthorizationCode(rawCode);

        var entity = new OAuthAuthorizationCode
        {
            Id = Guid.NewGuid(),
            CodeHash = codeHash,
            UserId = userId,
            ClientId = client.ClientId,
            RedirectUri = q.redirect_uri,
            CodeChallenge = q.code_challenge,
            CodeChallengeMethod = q.code_challenge_method,
            Scope = scope,
            Nonce = q.nonce,
            ExpiresAtUtc = DateTime.UtcNow.Add(CodeLifetime),
            Consumed = false,
        };
        _db.OAuthAuthorizationCodes.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        var okLocation = AppendQuery(q.redirect_uri, ("code", rawCode), ("state", q.state))!;
        return new OAuthAuthorizeOutcome { HasRedirect = true, RedirectLocation = okLocation };

        static OAuthAuthorizeOutcome BadOutcome() =>
            new() { HttpStatus = StatusCodes.Status400BadRequest, HttpBody = "invalid_request" };
    }

    public async Task<OAuthTokenOutcome> ExchangeCodeAsync(TokenFormRequest form, CancellationToken cancellationToken)
    {
        object Err(string error, string? desc, int code = 400) =>
            new { error, error_description = desc };

        if (string.Equals(form.grant_type, "refresh_token", StringComparison.Ordinal))
            return await ExchangeRefreshTokenAsync(form, cancellationToken);

        if (!string.Equals(form.grant_type, "authorization_code", StringComparison.Ordinal))
        {
            return new OAuthTokenOutcome
            {
                StatusCode = 400,
                Json = Err("unsupported_grant_type", "Use authorization_code."),
            };
        }

        if (string.IsNullOrWhiteSpace(form.code)
            || string.IsNullOrWhiteSpace(form.redirect_uri)
            || string.IsNullOrWhiteSpace(form.client_id)
            || string.IsNullOrWhiteSpace(form.code_verifier))
        {
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_request", "Parâmetros ausentes.") };
        }

        var hash = PkceVerifier.HashAuthorizationCode(form.code);
        var entry = await _db.OAuthAuthorizationCodes
            .FirstOrDefaultAsync(x => x.CodeHash == hash, cancellationToken);
        if (entry is null || entry.Consumed || entry.ExpiresAtUtc < DateTime.UtcNow)
        {
            return new OAuthTokenOutcome
            {
                StatusCode = 400,
                Json = Err("invalid_grant", "Código inválido ou expirado."),
            };
        }

        if (!string.Equals(entry.ClientId, form.client_id, StringComparison.Ordinal)
            || !string.Equals(entry.RedirectUri, form.redirect_uri, StringComparison.Ordinal))
        {
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "client_id ou redirect_uri não coincidem.") };
        }

        if (!PkceVerifier.VerifyS256(form.code_verifier, entry.CodeChallenge))
        {
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "PKCE code_verifier inválido.") };
        }

        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == entry.UserId && u.IsActive, cancellationToken);
        if (user is null)
        {
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "Usuário inativo.") };
        }

        var me = await _auth.GetMeAsync(entry.UserId, cancellationToken);
        if (me is null)
        {
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "Usuário não encontrado.") };
        }

        entry.Consumed = true;
        await _db.SaveChangesAsync(cancellationToken);

        var scopes = entry.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var groups = me.Groups.ToList();
        var perms = me.Permissions.ToList();
        var (accessToken, expiresIn) = _jwt.CreateAccessToken(user, groups, perms, scopes, form.client_id);
        var refreshToken = CreateRefreshToken(user.Id, form.client_id!, entry.Scope);
        _db.OAuthRefreshTokens.Add(refreshToken.Entity);
        await _db.SaveChangesAsync(cancellationToken);
        var includeOpenId = scopes.Any(s => s.Equals("openid", StringComparison.Ordinal));

        string? idToken = null;
        if (includeOpenId)
        {
            var (id, _) = _jwt.CreateIdToken(user, form.client_id!, entry.Nonce, groups);
            idToken = id;
        }

        return new OAuthTokenOutcome
        {
            StatusCode = 200,
            Json = new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = expiresIn,
                refresh_token = refreshToken.Raw,
                scope = entry.Scope,
                id_token = idToken,
            },
        };
    }

    public async Task RevokeAsync(RevokeFormRequest form, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(form.token))
            return;

        var hash = PkceVerifier.HashAuthorizationCode(form.token);
        var refresh = await _db.OAuthRefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, cancellationToken);
        if (refresh is not null)
        {
            if (string.IsNullOrEmpty(form.client_id) || string.Equals(refresh.ClientId, form.client_id, StringComparison.Ordinal))
            {
                refresh.Revoked = true;
                await _db.SaveChangesAsync(cancellationToken);
            }

            return;
        }

        var code = await _db.OAuthAuthorizationCodes.FirstOrDefaultAsync(x => x.CodeHash == hash, cancellationToken);
        if (code is not null && (string.IsNullOrEmpty(form.client_id) || string.Equals(code.ClientId, form.client_id, StringComparison.Ordinal)))
        {
            code.Consumed = true;
            await _db.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<object> IntrospectAsync(IntrospectFormRequest form, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(form.token))
            return new { active = false };

        if (!string.IsNullOrEmpty(form.token_type_hint) && string.Equals(form.token_type_hint, "refresh_token", StringComparison.Ordinal))
            return await IntrospectRefreshTokenAsync(form, cancellationToken);

        var refreshFirst = await IntrospectRefreshTokenCoreAsync(form.token, form.client_id, cancellationToken);
        if ((bool)refreshFirst.GetType().GetProperty("active")!.GetValue(refreshFirst)!)
            return refreshFirst;

        return IntrospectAccessToken(form.token, form.client_id);
    }

    private async Task<OAuthTokenOutcome> ExchangeRefreshTokenAsync(TokenFormRequest form, CancellationToken cancellationToken)
    {
        object Err(string error, string? desc) => new { error, error_description = desc };

        if (string.IsNullOrWhiteSpace(form.refresh_token) || string.IsNullOrWhiteSpace(form.client_id))
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_request", "refresh_token e client_id são obrigatórios.") };

        var hash = PkceVerifier.HashAuthorizationCode(form.refresh_token);
        var entry = await _db.OAuthRefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, cancellationToken);
        if (entry is null || entry.Revoked || entry.ExpiresAtUtc < DateTime.UtcNow)
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "Refresh token inválido ou expirado.") };

        if (!string.Equals(entry.ClientId, form.client_id, StringComparison.Ordinal))
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "client_id não coincide.") };

        var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == entry.UserId && u.IsActive, cancellationToken);
        if (user is null)
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "Usuário inativo.") };

        var me = await _auth.GetMeAsync(entry.UserId, cancellationToken);
        if (me is null)
            return new OAuthTokenOutcome { StatusCode = 400, Json = Err("invalid_grant", "Usuário não encontrado.") };

        entry.Revoked = true;
        var scopes = entry.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var groups = me.Groups.ToList();
        var perms = me.Permissions.ToList();
        var (accessToken, expiresIn) = _jwt.CreateAccessToken(user, groups, perms, scopes, entry.ClientId);
        var rotated = CreateRefreshToken(user.Id, entry.ClientId, entry.Scope);
        _db.OAuthRefreshTokens.Add(rotated.Entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new OAuthTokenOutcome
        {
            StatusCode = 200,
            Json = new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = expiresIn,
                refresh_token = rotated.Raw,
                scope = entry.Scope,
            },
        };
    }

    private static (string Raw, OAuthRefreshToken Entity) CreateRefreshToken(Guid userId, string clientId, string scope)
    {
        var raw = PkceVerifier.CreateAuthorizationCodeRaw();
        var entity = new OAuthRefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = PkceVerifier.HashAuthorizationCode(raw),
            UserId = userId,
            ClientId = clientId,
            Scope = scope,
            ExpiresAtUtc = DateTime.UtcNow.Add(RefreshTokenLifetime),
            Revoked = false,
        };

        return (raw, entity);
    }

    private async Task<object> IntrospectRefreshTokenAsync(IntrospectFormRequest form, CancellationToken cancellationToken)
    {
        return await IntrospectRefreshTokenCoreAsync(form.token!, form.client_id, cancellationToken);
    }

    private async Task<object> IntrospectRefreshTokenCoreAsync(string rawToken, string? clientId, CancellationToken cancellationToken)
    {
        var hash = PkceVerifier.HashAuthorizationCode(rawToken);
        var entry = await _db.OAuthRefreshTokens.AsNoTracking().FirstOrDefaultAsync(x => x.TokenHash == hash, cancellationToken);
        if (entry is null || entry.Revoked || entry.ExpiresAtUtc < DateTime.UtcNow)
            return new { active = false };

        if (!string.IsNullOrEmpty(clientId) && !string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
            return new { active = false };

        return new
        {
            active = true,
            token_type = "refresh_token",
            client_id = entry.ClientId,
            sub = entry.UserId.ToString(),
            scope = entry.Scope,
            exp = new DateTimeOffset(entry.ExpiresAtUtc).ToUnixTimeSeconds(),
        };
    }

    private object IntrospectAccessToken(string rawToken, string? clientId)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(
                rawToken,
                new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = "lrf.auth",
                    ValidateAudience = true,
                    ValidAudience = "lrf.auth",
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _signingKeys.SecurityKey,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                },
                out var validatedToken);

            var jwt = (JwtSecurityToken)validatedToken;
            var tokenClientId = principal.FindFirst("client_id")?.Value;
            if (!string.IsNullOrEmpty(clientId) && !string.Equals(tokenClientId, clientId, StringComparison.Ordinal))
                return new { active = false };

            var scopes = principal.FindAll("scope").Select(x => x.Value).ToArray();
            return new
            {
                active = true,
                token_type = "access_token",
                client_id = tokenClientId,
                sub = principal.FindFirst("sub")?.Value,
                username = principal.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value,
                scope = string.Join(' ', scopes),
                exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
                iat = new DateTimeOffset(jwt.ValidFrom).ToUnixTimeSeconds(),
            };
        }
        catch
        {
            return new { active = false };
        }
    }
}
