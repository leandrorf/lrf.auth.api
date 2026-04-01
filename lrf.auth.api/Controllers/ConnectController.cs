using System.Security.Claims;
using lrf.auth.api.Contracts;
using lrf.auth.api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace lrf.auth.api.Controllers;

[Route("connect")]
public sealed class ConnectController : ControllerBase
{
    private readonly IOAuthConnectService _oauth;
    private readonly string[] _allowedPostLogoutOrigins;

    public ConnectController(IOAuthConnectService oauth, IConfiguration configuration)
    {
        _oauth = oauth;
        _allowedPostLogoutOrigins = configuration.GetSection("Cors:WebOrigins").Get<string[]>()
                                     ?? Array.Empty<string>();
    }

    /// <summary>Encerra a sessão cookie do IdP (fluxo OAuth). Opcional: <c>returnUrl</c> deve ser origem permitida (Cors:WebOrigins).</summary>
    [HttpGet("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout([FromQuery] string? returnUrl)
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!string.IsNullOrWhiteSpace(returnUrl)
            && IsPostLogoutRedirectAllowed(returnUrl))
            return Redirect(returnUrl);

        return Redirect("/connect/login");
    }

    private bool IsPostLogoutRedirectAllowed(string returnUrl)
    {
        if (returnUrl.Length > 2048)
            return false;
        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return false;

        var authority = $"{uri.Scheme}://{uri.Authority}".TrimEnd('/');
        foreach (var origin in _allowedPostLogoutOrigins)
        {
            var o = origin.Trim().TrimEnd('/');
            if (string.Equals(authority, o, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>OAuth 2.0 Authorization Endpoint (código + PKCE S256). Exige sessão cookie no IdP.</summary>
    [HttpGet("authorize")]
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequestQuery query, CancellationToken cancellationToken)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (sub is null || !Guid.TryParse(sub, out var userId))
            return Unauthorized();

        var outcome = await _oauth.AuthorizeAsync(query, userId, cancellationToken);
        if (outcome.HasRedirect && !string.IsNullOrEmpty(outcome.RedirectLocation))
            return Redirect(outcome.RedirectLocation);

        if (outcome.HttpStatus is { } status)
            return StatusCode(status, outcome.HttpBody);

        return BadRequest();
    }

    /// <summary>OAuth 2.0 Token Endpoint (authorization_code + PKCE).</summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] TokenFormRequest form, CancellationToken cancellationToken)
    {
        var outcome = await _oauth.ExchangeCodeAsync(form, cancellationToken);
        return StatusCode(outcome.StatusCode, outcome.Json);
    }

    /// <summary>Revoga authorization code ou refresh token do cliente.</summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Revoke([FromForm] RevokeFormRequest form, CancellationToken cancellationToken)
    {
        await _oauth.RevokeAsync(form, cancellationToken);
        return Ok();
    }

    /// <summary>Introspection endpoint para access_token e refresh_token.</summary>
    [HttpPost("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Introspect([FromForm] IntrospectFormRequest form, CancellationToken cancellationToken)
    {
        var json = await _oauth.IntrospectAsync(form, cancellationToken);
        return Ok(json);
    }
}
