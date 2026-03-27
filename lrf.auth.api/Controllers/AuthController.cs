using System.Security.Claims;
using lrf.auth.api.Authorization;
using lrf.auth.api.Contracts;
using lrf.auth.api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace lrf.auth.api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _auth;

    public AuthController(IAuthService auth)
    {
        _auth = auth;
    }

    /// <summary>Cadastro de usuário exige permissão de escrita (<see cref="AuthPolicies.UsersCreate"/>).</summary>
    [Authorize(Policy = AuthPolicies.UsersCreate)]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        var (ok, error) = await _auth.RegisterAsync(request, cancellationToken);
        if (!ok)
            return Problem(detail: error, statusCode: StatusCodes.Status400BadRequest);

        return NoContent();
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        var (ok, body, error) = await _auth.LoginAsync(request, cancellationToken);
        if (!ok || body is null)
            return Problem(detail: error, statusCode: StatusCodes.Status401Unauthorized, title: "Não autorizado");

        return Ok(body);
    }

    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(typeof(MeResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<MeResponse>> Me(CancellationToken cancellationToken)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        if (sub is null || !Guid.TryParse(sub, out var userId))
            return Unauthorized();

        var me = await _auth.GetMeAsync(userId, cancellationToken);
        if (me is null)
            return NotFound();

        return Ok(me);
    }
}
