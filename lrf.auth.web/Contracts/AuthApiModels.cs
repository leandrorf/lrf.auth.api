using System.Text.Json.Serialization;

namespace lrf.auth.web.Contracts;

public sealed class AuthResponseDto
{
    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("tokenType")]
    public string? TokenType { get; set; }

    [JsonPropertyName("expiresInSeconds")]
    public int ExpiresInSeconds { get; set; }
}

public sealed class MeResponseDto
{
    [JsonPropertyName("userId")]
    public Guid UserId { get; set; }

    [JsonPropertyName("email")]
    public string? Email { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("groups")]
    public List<string> Groups { get; set; } = new();

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = new();
}
