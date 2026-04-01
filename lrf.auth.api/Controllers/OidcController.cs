using System.Security.Claims;
using lrf.auth.api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace lrf.auth.api.Controllers;

[ApiController]
public sealed class OidcController : ControllerBase
{
    private readonly JwtOptionsAccessor _options;
    private readonly IOidcSigningKeyService _signingKeys;
    private readonly IAuthService _auth;

    public OidcController(IOidcSigningKeyService signingKeys, IConfiguration configuration, IAuthService auth)
    {
        _signingKeys = signingKeys;
        _auth = auth;
        _options = new JwtOptionsAccessor
        {
            Issuer = configuration.GetSection("Jwt")["Issuer"] ?? "",
        };
    }

    [HttpGet(".well-known/openid-configuration")]
    [AllowAnonymous]
    public IActionResult Discovery()
    {
        var issuer = BuildIssuer();
        return Ok(new
        {
            issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            userinfo_endpoint = $"{issuer}/connect/userinfo",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            token_endpoint_auth_methods_supported = new[] { "none" },
            code_challenge_methods_supported = new[] { "S256" },
            scopes_supported = new[] { "openid", "profile", "email" },
            claims_supported = new[] { "sub", "email", "name", "groups" },
        });
    }

    [HttpGet(".well-known/jwks.json")]
    [AllowAnonymous]
    public IActionResult Jwks()
    {
        return Ok(new { keys = new[] { _signingKeys.GetJwk() } });
    }

    [HttpGet("connect/userinfo")]
    [Authorize]
    public async Task<IActionResult> UserInfo(CancellationToken cancellationToken)
    {
        var sub = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (sub is null || !Guid.TryParse(sub, out var userId))
            return Unauthorized();

        var scopes = User.FindAll("scope").Select(x => x.Value).ToHashSet(StringComparer.Ordinal);
        if (!scopes.Contains("openid"))
            return Forbid();

        var me = await _auth.GetMeAsync(userId, cancellationToken);
        if (me is null)
            return NotFound();

        return Ok(new
        {
            sub = me.UserId,
            name = scopes.Contains("profile") ? me.UserName : null,
            preferred_username = scopes.Contains("profile") ? me.UserName : null,
            email = scopes.Contains("email") ? me.Email : null,
            email_verified = scopes.Contains("email") ? (bool?)true : null,
            groups = scopes.Contains("profile") ? me.Groups : null,
        });
    }

    private string BuildIssuer()
    {
        if (!string.IsNullOrWhiteSpace(_options.Issuer)
            && Uri.TryCreate(_options.Issuer, UriKind.Absolute, out var configured))
            return configured.ToString().TrimEnd('/');
        return $"{Request.Scheme}://{Request.Host}";
    }

    private sealed class JwtOptionsAccessor
    {
        public string Issuer { get; init; } = "";
    }
}
