using System.ComponentModel.DataAnnotations;

namespace lrf.auth.api.Contracts;

public sealed class RegisterRequest
{
    [Required, EmailAddress, MaxLength(320)]
    public string Email { get; set; } = "";

    [Required, MinLength(1), MaxLength(256)]
    public string UserName { get; set; } = "";

    [Required, MinLength(8), MaxLength(200)]
    public string Password { get; set; } = "";
}

public sealed class LoginRequest
{
    [Required, EmailAddress, MaxLength(320)]
    public string Email { get; set; } = "";

    [Required, MinLength(1), MaxLength(200)]
    public string Password { get; set; } = "";
}

public sealed class AuthResponse
{
    public string AccessToken { get; set; } = "";

    public string TokenType { get; set; } = "Bearer";

    public int ExpiresInSeconds { get; set; }
}

public sealed class MeResponse
{
    public Guid UserId { get; set; }

    public string Email { get; set; } = "";

    public string UserName { get; set; } = "";

    public IReadOnlyList<string> Groups { get; set; } = Array.Empty<string>();

    public IReadOnlyList<string> Permissions { get; set; } = Array.Empty<string>();
}
