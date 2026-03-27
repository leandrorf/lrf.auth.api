using System.Security.Cryptography;
using System.Text;

namespace lrf.auth.api.OAuth;

public static class PkceVerifier
{
    public static bool VerifyS256(string codeVerifier, string codeChallenge)
    {
        if (string.IsNullOrWhiteSpace(codeVerifier) || string.IsNullOrWhiteSpace(codeChallenge))
            return false;

        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var expected = Base64UrlEncode(hash);
        var a = Encoding.UTF8.GetBytes(expected);
        var b = Encoding.UTF8.GetBytes(codeChallenge);
        if (a.Length != b.Length)
            return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    public static string HashAuthorizationCode(string rawCode)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(rawCode));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string CreateAuthorizationCodeRaw()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
