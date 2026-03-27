namespace lrf.auth.api.Options;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; set; } = "";

    public string Audience { get; set; } = "";

    /// <summary>Chave simétrica (HMAC-SHA256). Use pelo menos 32 caracteres.</summary>
    public string SigningKey { get; set; } = "";

    public int AccessTokenMinutes { get; set; } = 60;
}
