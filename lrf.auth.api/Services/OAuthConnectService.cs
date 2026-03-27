using lrf.auth.api.Contracts;
using lrf.auth.api.Data;
using lrf.auth.api.Domain.Entities;
using lrf.auth.api.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace lrf.auth.api.Services;

public sealed class OAuthConnectService : IOAuthConnectService
{
    private readonly AuthDbContext _db;
    private readonly IJwtTokenService _jwt;
    private readonly IAuthService _auth;

    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);

    public OAuthConnectService(AuthDbContext db, IJwtTokenService jwt, IAuthService auth)
    {
        _db = db;
        _jwt = jwt;
        _auth = auth;
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

        var groups = me.Groups.ToList();
        var perms = me.Permissions.ToList();
        var (accessToken, expiresIn) = _jwt.CreateAccessToken(user, groups, perms, form.client_id);

        var scopes = entry.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
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
                scope = entry.Scope,
                id_token = idToken,
            },
        };
    }
}
