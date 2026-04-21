using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Minedu.VC.Verifier.Services
{
    public class DidWebResolver
    {
        private readonly HttpClient _http;
        private readonly ILogger<VerificationService> _logger;

        public DidWebResolver(HttpClient httpClient, ILogger<VerificationService> logger)
        {
            _http = httpClient;
            _logger = logger;
        }

        public async Task<ResolvedKey?> ResolveKeyAsync(string didWeb, string kidOrFragment)
        {
            _logger.LogInformation("Iniciando funcion ResolveKeyAsync | didWeb={didWeb} | kidOrFragment={kidOrFragment}", didWeb, kidOrFragment);
            // did:web:example.com -> https://example.com/.well-known/did.json
            // did:web:example.com:sub -> https://example.com/sub/did.json

            if (!didWeb.StartsWith("did:web:", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("El DID no es válido, debe empezar con 'did:web:'.");
                return null;
            }

            //prepara url para request
            var withoutPrefix = didWeb.Substring("did:web:".Length);
            var parts = withoutPrefix.Split(':');
            var host = parts[0];
            var path = parts.Length > 1 ? "/" + string.Join("/", parts.Skip(1)) : "";
            var url = $"https://{host}{(string.IsNullOrEmpty(path) ? "/.well-known/did.json" : path + "/did.json")}";

            _logger.LogInformation("Invocando petición a Url que se usará para resolver del DID: {url}", url);

            //llamada para obtener did.json del emisor
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            var res = await _http.SendAsync(req);
            res.EnsureSuccessStatusCode();

            _logger.LogInformation("Se termina la llamada a Url usada para resolver el DID. Response: {res}", res.Content.ReadAsStringAsync());

            //deserializa el documento json did.json
            var json = await res.Content.ReadAsStringAsync();
            var didDoc = JsonSerializer.Deserialize<DidDocument>(json, JsonOptions());

            if (didDoc?.VerificationMethod == null)
            {
                _logger.LogError("El campo VerificationMethod del DID obtenido no debe ser nulo.");
                return null;
            }

            // Normalize kid: may come like "did:web:...#keys-1" or just "#keys-1"
            string target = kidOrFragment.StartsWith("#") ? $"{didWeb}{kidOrFragment}" : kidOrFragment;
            _logger.LogInformation("Se obtiene el valor de la llave criptografica a validar por el verificador: {target}", target);

            var vm = didDoc.VerificationMethod.FirstOrDefault(v => string.Equals(v.Id, target, StringComparison.OrdinalIgnoreCase));
            _logger.LogInformation("Se obtiene el valor del VerificationMethod a validar por el verificador: {vm}", vm);

            if (vm == null)
            {
                _logger.LogError("VerificationMethod no puede ser nulo.");
                return null;
            } 

            // Prefer JWK if present; fallback to multibase
            if (vm.PublicKeyJwk != null && 
                vm.PublicKeyJwk.TryGetValue("kty", out var kty) &&
                kty.ValueKind == JsonValueKind.String &&
                kty.GetString() == "OKP")
            {
                _logger.LogInformation("Se detecta vm.PublicKeyJwk presente: {PublicKeyJwk}", vm.PublicKeyJwk.ToString());

                if (vm.PublicKeyJwk.TryGetValue("crv", out var crvElem) &&
                    vm.PublicKeyJwk.TryGetValue("x", out var xElem) &&
                    crvElem.ValueKind == JsonValueKind.String &&
                    xElem.ValueKind == JsonValueKind.String)
                {
                    var crv = crvElem.GetString();
                    var x = xElem.GetString();

                    if (string.Equals(crv, "Ed25519", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(x))
                    {
                        return new ResolvedKey
                        {
                            Kid = vm.Id,
                            Alg = "EdDSA",
                            Crv = "Ed25519",
                            PublicKey = Base64UrlDecode(x!)
                        };
                    }
                }
            }
            else if (!string.IsNullOrEmpty(vm.PublicKeyMultibase))
            {
                _logger.LogInformation("Se detecta vm.PublicKeyMultibase presente: {PublicKeyMultibase}", vm.PublicKeyMultibase.ToString());

                // Multibase 'z' (base58-btc) commonly used for Ed25519 public keys
                var pk = MultiBaseDecode(vm.PublicKeyMultibase);
                return new ResolvedKey
                {
                    Kid = vm.Id,
                    Alg = "EdDSA",
                    Crv = "Ed25519",
                    PublicKey = pk
                };
            }
            _logger.LogError("No se detecta un VerificationMethod soportado.");
            return null;
        }

        public class ResolvedKey
        {
            public string Kid { get; set; } = default!;
            public string Alg { get; set; } = default!;
            public string Crv { get; set; } = default!;
            public byte[] PublicKey { get; set; } = default!;
        }

        // ---------- internal DTOs ----------
        public class DidDocument
        {
            [JsonPropertyName("@context")]
            public object? Context { get; set; }
            public string? Id { get; set; }
            public List<VerificationMethodEntry>? VerificationMethod { get; set; }
        }

        private static byte[] Base64UrlDecode(string s)
        {
            string pad = new string('=', (4 - s.Length % 4) % 4);
            s = s.Replace('-', '+').Replace('_', '/') + pad;
            return Convert.FromBase64String(s);
        }

        private static byte[] MultiBaseDecode(string multibase)
        {
            // Expect multibase like "z<base58btc>"
            if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
                throw new NotSupportedException("Only base58-btc multibase supported here.");
            var b58 = multibase.Substring(1);
            var data = Base58Bitcoin.Decode(b58);

            // Handle multicodec header (0xED 0x01 for Ed25519)
            if (data.Length == 34 && data[0] == 0xED && data[1] == 0x01)
            {
                // Remove first two bytes
                data = data.Skip(2).ToArray();
            }

            return data;
        }

        private static JsonSerializerOptions JsonOptions()
        {
            return new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
        }

        // ---------- minimal Base58 for multibase decode ----------
        private static class Base58Bitcoin
        {
            private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            public static byte[] Decode(string s)
            {
                var intData = System.Numerics.BigInteger.Zero;
                foreach (char c in s)
                {
                    int digit = Alphabet.IndexOf(c);
                    if (digit < 0) throw new FormatException($"Invalid Base58 character `{c}`");
                    intData = intData * 58 + digit;
                }
                // Leading zero bytes
                int leadingZeroCount = s.TakeWhile(ch => ch == '1').Count();
                var bytes = intData.ToByteArray(isBigEndian: true);
                // Remove sign if present
                if (bytes.Length > 0 && bytes[0] == 0x00)
                    bytes = bytes.Skip(1).ToArray();
                return Enumerable.Repeat((byte)0x00, leadingZeroCount).Concat(bytes).ToArray();
            }
        }

        public class VerificationMethodEntry
        {
            public string Id { get; set; } = default!;
            public string Type { get; set; } = default!;
            public string Controller { get; set; } = default!;
            [JsonPropertyName("publicKeyMultibase")]
            public string? PublicKeyMultibase { get; set; }
            [JsonPropertyName("publicKeyJwk")]
            public Dictionary<string, JsonElement>? PublicKeyJwk { get; set; }
        }
    }
}