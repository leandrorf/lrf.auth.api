using System.ComponentModel.DataAnnotations;

namespace lrf.auth.api.Contracts;

public sealed class AuthorizeRequestQuery
{
    public string? client_id { get; set; }

    public string? redirect_uri { get; set; }

    public string? response_type { get; set; }

    public string? scope { get; set; }

    public string? state { get; set; }

    public string? code_challenge { get; set; }

    public string? code_challenge_method { get; set; }

    public string? nonce { get; set; }
}

public sealed class TokenFormRequest
{
    [Required]
    public string? grant_type { get; set; }

    public string? code { get; set; }

    public string? redirect_uri { get; set; }

    public string? client_id { get; set; }

    public string? code_verifier { get; set; }

    public string? refresh_token { get; set; }
}

public sealed class RevokeFormRequest
{
    [Required]
    public string? token { get; set; }

    public string? client_id { get; set; }

    public string? token_type_hint { get; set; }
}

public sealed class IntrospectFormRequest
{
    [Required]
    public string? token { get; set; }

    public string? client_id { get; set; }

    public string? token_type_hint { get; set; }
}
