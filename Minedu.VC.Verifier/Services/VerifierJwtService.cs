using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;
using NSec.Cryptography;
using System.Text;
using System.Text.Json;

namespace Minedu.VC.Verifier.Services
{
    public class VerifierJwtService
    {
        private readonly VerifierConfig _config;
        private readonly IWebHostEnvironment _env;

        public VerifierJwtService(IOptions<VerifierConfig> cfg, IWebHostEnvironment env)
        {
            _config = cfg.Value;
            _env = env;
        }

        public string CreateRequestJwt(object claims)
        {
            var keyPath = Path.Combine(_env.ContentRootPath, "Keys", "verifier-key.json");
            var jwk = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(keyPath));

            var d = Base64UrlDecode(jwk.GetProperty("d").GetString()!);
            var kid = jwk.GetProperty("kid").GetString()!;

            var header = new { alg = "EdDSA", typ = "JWT", kid };
            var headerJson = JsonSerializer.Serialize(header);
            var payloadJson = JsonSerializer.Serialize(claims);

            var headerB64  = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            var signingInput = Encoding.UTF8.GetBytes($"{headerB64}.{payloadB64}");

            using var key = Key.Import(SignatureAlgorithm.Ed25519, d, KeyBlobFormat.RawPrivateKey);
            var sig = SignatureAlgorithm.Ed25519.Sign(key, signingInput);

            return $"{headerB64}.{payloadB64}.{Base64UrlEncode(sig)}";
        }

        private static string Base64UrlEncode(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static byte[] Base64UrlDecode(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
            return Convert.FromBase64String(s);
        }
    }
}
