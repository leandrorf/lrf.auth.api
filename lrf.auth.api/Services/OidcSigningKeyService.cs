using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace lrf.auth.api.Services;

public interface IOidcSigningKeyService
{
    RsaSecurityKey SecurityKey { get; }

    SigningCredentials SigningCredentials { get; }

    string KeyId { get; }

    object GetJwk();
}

public sealed class OidcSigningKeyService : IOidcSigningKeyService
{
    private readonly RSA _rsa = RSA.Create(2048);

    public OidcSigningKeyService()
    {
        SecurityKey = new RsaSecurityKey(_rsa.ExportParameters(true))
        {
            KeyId = Base64UrlEncoder.Encode(SHA256.HashData(_rsa.ExportSubjectPublicKeyInfo())),
        };
        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256);
    }

    public RsaSecurityKey SecurityKey { get; }

    public SigningCredentials SigningCredentials { get; }

    public string KeyId => SecurityKey.KeyId!;

    public object GetJwk()
    {
        var parameters = _rsa.ExportParameters(false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid = KeyId,
            n = Base64UrlEncoder.Encode(parameters.Modulus!),
            e = Base64UrlEncoder.Encode(parameters.Exponent!),
        };
    }
}
