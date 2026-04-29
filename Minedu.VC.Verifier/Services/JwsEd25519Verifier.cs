using NSec.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace Minedu.VC.Verifier.Services
{
    public class JwsEd25519Verifier
    {
        public static bool VerifyCompactJws(string jwsCompact, byte[] publicKey)
        {
            // Format: BASE64URL(ProtectedHeader) '.' BASE64URL(Payload) '.' BASE64URL(Signature)
            var parts = jwsCompact.Split('.');
            if (parts.Length != 3) return false;

            var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            var signature = Base64UrlDecode(parts[2]);

            var alg = SignatureAlgorithm.Ed25519;
            var pubKey = PublicKey.Import(alg, publicKey, KeyBlobFormat.RawPublicKey);

            return alg.Verify(pubKey, signingInput, signature);
        }

        public static byte[]? GetPayload(string jwsCompact)
        {
            var parts = jwsCompact.Split('.');
            if (parts.Length != 3) return null;
            return Base64UrlDecode(parts[1]);
        }

        public static (string headerJson, string payloadJson)? GetDecodedParts(string jwsCompact)
        {
            var parts = jwsCompact.Split('.');
            if (parts.Length != 3) return null;
            var header = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            var payload = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            return (header, payload);
        }

        private static byte[] Base64UrlDecode(string s)
        {
            string pad = new string('=', (4 - s.Length % 4) % 4);
            s = s.Replace('-', '+').Replace('_', '/') + pad;
            return Convert.FromBase64String(s);
        }

        public static bool VerifyDetachedJws(string protectedHeaderB64, string detachedPayload, string signatureB64, byte[] publicKey)
        {
            // ASCII para JSON canónico de VC (el emisor también usa ASCII para el signing input)
            var signingInput = Encoding.ASCII.GetBytes($"{protectedHeaderB64}.{detachedPayload}");
            var signature = Base64UrlDecode(signatureB64);

            var alg = SignatureAlgorithm.Ed25519;
            var pubKey = PublicKey.Import(alg, publicKey, KeyBlobFormat.RawPublicKey);

            return alg.Verify(pubKey, signingInput, signature);
        }

        // Versión para VP holder binding: el payload ya viene como bytes UTF-8 (de JSON sin \uXXXX escaping)
        public static bool VerifyDetachedJwsRawBytes(string protectedHeaderB64, byte[] payloadBytes, string signatureB64, byte[] publicKey)
        {
            var headerPart = Encoding.ASCII.GetBytes(protectedHeaderB64 + ".");
            var signingInput = new byte[headerPart.Length + payloadBytes.Length];
            Buffer.BlockCopy(headerPart, 0, signingInput, 0, headerPart.Length);
            Buffer.BlockCopy(payloadBytes, 0, signingInput, headerPart.Length, payloadBytes.Length);

            var signature = Base64UrlDecode(signatureB64);
            var alg = SignatureAlgorithm.Ed25519;
            var pubKey = PublicKey.Import(alg, publicKey, KeyBlobFormat.RawPublicKey);
            return alg.Verify(pubKey, signingInput, signature);
        }

        public static bool IsDetached(string protectedHeaderB64)
        {
            var json = Encoding.UTF8.GetString(Base64UrlDecode(protectedHeaderB64));
            return json.Contains("\"b64\":false", StringComparison.OrdinalIgnoreCase);
        }
    }
}
