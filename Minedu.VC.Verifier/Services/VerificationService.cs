using Microsoft.AspNetCore.Mvc.RazorPages;
using Minedu.VC.Verifier.Models;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Minedu.VC.Verifier.Services
{
    public class VerificationService
    {
        private readonly TrustedIssuerService _trust;
        private readonly DidWebResolver _did;
        private readonly AttendeeService _attendees;
        private readonly ILogger<VerificationService> _logger;
        private readonly string _logPath;

        public VerificationService(TrustedIssuerService trust, DidWebResolver did, AttendeeService attendees, ILogger<VerificationService> logger, string logPath)
        {
            _trust = trust;
            _did = did;
            _attendees = attendees;
            _logger = logger;
            _logPath = logPath;
        }

        public async Task<VerificationResult> VerifyPresentationAsync(string vpToken)
        {
            // Placeholder: en el futuro aquí validas la firma, issuer y PD
            if (string.IsNullOrWhiteSpace(vpToken))
            {
                _logger.LogWarning("vp_token faltante o vacío.");
                return Fail("Falta vp_token");
            }

            _logger.LogInformation("🔍 Iniciando verificación base del vp_token ({Length} caracteres)", vpToken.Length);
             
            try
            {
                // Heurística simple: si tiene dos puntos (.) => parece JWS compacto
                if (vpToken.Count(c => c == '.') == 2)
                {
                    _logger.LogInformation("Detectado formato JWS compacto (EdDSA probable)");
                    var result = await VerifyAsCompactJwsAsync(vpToken);
                    _logger.LogInformation("Verificación JWS completada | Valid={Valid} | Issuer={Issuer}", result.Valid, result.Issuer);
                    return result;
                }

                // Caso JSON/JSON-LD con proof.jws
                if (vpToken.TrimStart().StartsWith("{"))
                {
                    _logger.LogInformation("Detectado formato JSON-LD (proof.jws embebido o detached)");
                    _logger.LogInformation("Enviando vp_token a VerificationService.VerifyAsJsonLdAsync");
                    var result = await VerifyAsJsonLdAsync(vpToken);
                    _logger.LogInformation("Verificación JSON-LD completada | Valid={Valid} | Issuer={Issuer}", result.Valid, result.Issuer);
                    return result;
                }

                // Caso formato no soportado
                _logger.LogWarning("Formato de vp_token no soportado ({Sample})", vpToken.Substring(0, Math.Min(50, vpToken.Length)));
                return Fail("Formato de vp_token no soportado.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Excepción durante la verificación del vp_token");
                return Fail($"Excepción durante la verificación: {ex.Message}");
            }
        }

        // -------- Ruta A: JWT/JWS compacto --------
        private async Task<VerificationResult> VerifyAsCompactJwsAsync(string jws)
        {
            _logger.LogInformation("Inicia verificación de vpToken con formato JWT/JWS compacto");

            var parts = JwsEd25519Verifier.GetDecodedParts(jws);
            if (parts == null) {
                _logger.LogWarning("El vp_token en formato JWS no esta bien confirmado.");
                return Fail("El vp_token en formato JWS no esta bien confirmado.");
            } 

            var (headerJson, payloadJson) = parts.Value;
            var header = JsonNode.Parse(headerJson)!.AsObject();
            var kid = header["kid"]?.GetValue<string>();
            var alg = header["alg"]?.GetValue<string>();
            _logger.LogInformation("Cabecera JWS detectada | alg={Alg} | kid={Kid}", alg ?? "—", kid ?? "—");

            if (!string.Equals(alg, "EdDSA", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Algoritmo no soportado {alg} (Se esperaba EdDSA) .", alg);
                return Fail("Unsupported alg (expected EdDSA)");
            }
                
            // El payload puede ser un VP o una VC embebida
            var payload = JsonNode.Parse(payloadJson)!.AsObject();

            // Intentamos localizar issuer/credential
            string? issuer = payload["iss"]?.GetValue<string>(); // típico JWT
            JsonNode? vcNode = payload["vc"] ?? payload["verifiableCredential"];
            JsonNode? vpNode = payload["vp"] ?? payload["verifiablePresentation"];

            // Caso: si es VP, adentro puede haber VC(s)
            if (issuer == null && vpNode is JsonObject vpObj)
            {
                var vcs = vpObj["verifiableCredential"];
                if (vcs is JsonArray arr && arr.Count > 0)
                {
                    var firstVc = arr[0];
                    issuer = firstVc?["issuer"]?.GetValue<string>();
                }
            }

            // Caso: si es VC directa
            if (issuer == null && vcNode is JsonObject vcObj)
            {
                issuer = vcObj["issuer"]?.GetValue<string>();
            }

            if (string.IsNullOrEmpty(issuer)) 
            {
                _logger.LogWarning("No se pudo determinar el issuer desde el payload JWS.");
                return Fail("Cannot determine issuer from payload");
            }
            _logger.LogInformation("Issuer detectado en payload: {Issuer}", issuer);

            if (!_trust.IsTrusted(issuer))
            {
                _logger.LogWarning("Issuer no confiable | Issuer={Issuer}", issuer);
                return Fail($"Untrusted issuer: {issuer}");
            }


            if (string.IsNullOrEmpty(kid)) 
            {
                _logger.LogWarning("Falta el parámetro 'kid' en la cabecera del JWS para el issuer {Issuer}", issuer);
                return Fail("Missing kid in JWS header");
            }

            _logger.LogInformation("Resolviendo clave pública Ed25519 desde DID | Issuer={Issuer} | Kid={Kid}", issuer, kid);
            var key = await _did.ResolveKeyAsync(issuer, kid);
            if (key == null || key.Crv != "Ed25519")
            {
                _logger.LogWarning("No se pudo resolver la clave pública Ed25519 desde DID | Issuer={Issuer}", issuer);
                return Fail("Cannot resolve Ed25519 public key from DID");
            }

            _logger.LogInformation("Verificando firma Ed25519...");
            var valid = JwsEd25519Verifier.VerifyCompactJws(jws, key.PublicKey);
            if (!valid) 
            {
                _logger.LogWarning("Firma Ed25519 inválida en el jws. Llave pública {key.PublicKey}.", key.PublicKey);
                return Fail("Invalid signature"); 
            }
            _logger.LogInformation("Firma Ed25519 válida | Issuer={Issuer}", issuer);

            // Extract a subject if present (DNI)
            string? subject = TryExtractSubject(payload);
            _logger.LogInformation("Subject extraído del payload: {Subject}", subject ?? "(no disponible)");

            return new VerificationResult
            {
                Valid = true,
                Reason = "OK",
                Issuer = issuer,
                Subject = subject
            };
        }

        private async Task<VerificationResult> VerifyAsJsonLdAsync(string json)
        {
            _logger.LogInformation("Inicia verificación de presentación en formato JSON-LD.");

            var checks = new List<VerificationCheck>();
            
            JsonObject? root;
            try
            {
                root = JsonNode.Parse(json)!.AsObject();
                _logger.LogInformation("Se obtuvo elemento root correctamente del objeto Json.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al parsear JSON de la presentación.");
                return Fail("JSON inválido o malformado.");
            }

            // Soportar formato Inji VP: { verifiableCredential: [{...VC...}], proof: {...VP proof...} }
            JsonNode? vc;
            var vcArray = root["verifiableCredential"] as JsonArray;
            if (vcArray != null && vcArray.Count > 0)
            {
                vc = vcArray[0] as JsonObject;
                _logger.LogInformation("VC extraída de verifiableCredential[0] (formato OID4VP/Inji)");
            }
            else
            {
                var data = root["data"] as JsonObject ?? root;
                vc = data["vc"] ?? data;
                _logger.LogInformation("VC extraída desde raíz o data.vc");
            }

            // El proof para verificar es el de la VC (firmado por el issuer)
            var proof = vc?["proof"];

            if (proof is not JsonObject p)
            {
                _logger.LogWarning("Falta el objeto 'proof' en la VC.");
                return Fail("Falta la prueba de la vc.");
            }

            _logger.LogInformation("Se obtuvo elemento vc y proof correctamente del objeto Json.");

            //verificationMethod and jws from VC(JSON-LD)
            var jws = p["jws"]?.GetValue<string>();
            var verificationMethod = p["verificationMethod"]?.GetValue<string>();

            _logger.LogInformation("Se obtuvo elemento jws: {jws}", jws);
            _logger.LogInformation("Se obtuvo elemento verificationMethod: {verificationMethod}", verificationMethod);

            if (string.IsNullOrEmpty(jws) || string.IsNullOrEmpty(verificationMethod))
            {
                _logger.LogWarning("Faltan campos obligatorios en el proof: jws ({jwsLength}) o verificationMethod ({vmLength}).", jws?.Length, verificationMethod?.Length);
                return Fail("Falta proof.jws o verificationMethod");
            }

            // Issuer from VC (JSON-LD)
            var issuer = vc?["issuer"]?.GetValue<string>();
            if (string.IsNullOrEmpty(issuer))
            {
                _logger.LogWarning("Issuer ausente en la VC JSON-LD.");
                return Fail("Issuer ausente en la VC");
            }

            _logger.LogInformation("Issuer detectado en VC: {Issuer}", issuer);
            checks.Add(new VerificationCheck { Name = "Issuer presente", Passed = true, Message = "OK" });

            if (!_trust.IsTrusted(issuer))
            {
                _logger.LogWarning("Issuer no confiable: {Issuer}", issuer);
                checks.Add(new VerificationCheck { Name = "Issuer confiable", Passed = false, Message = $"Untrusted issuer: {issuer}" });
            }
            else
            {
                _logger.LogWarning("Issuer confiable: {Issuer}", issuer);
                checks.Add(new VerificationCheck { Name = "Issuer confiable", Passed = true, Message = "OK" });
            }
            

            // Normalizar kid: verificationMethod actúa como kid completo
            _logger.LogInformation("Resolviendo clave pública desde DID | Issuer={Issuer} | VerificationMethod={Method}", issuer, verificationMethod);
            var key = await _did.ResolveKeyAsync(issuer, verificationMethod);
            if (key == null || key.Crv != "Ed25519")
            {
                _logger.LogWarning("No se pudo resolver la clave Ed25519 desde el DID del issuer {Issuer}.", issuer);
                return Fail("No puede resolverse llave publica Ed25519 del DID");
            }


            // ===================================================
            // 🔍 VERIFICACIÓN DE FIRMA DESACOPLADA (b64=false)
            // ===================================================
            _logger.LogInformation("Verificando firma JSON-LD (b64={B64})", JwsEd25519Verifier.IsDetached(jws.Split('.')[0]) ? "false" : "true");

            var parts = jws!.Split('.');
            if (parts.Length != 3)
            {
                _logger.LogWarning("Formato JWS inválido en prueba JSON-LD.");
                return Fail("Formato JWS inválido.");
            }
                
            var protectedHeader = parts[0];
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(vc!.ToJsonString())); // payload original de la VC
            var signature = parts[2];

            bool ok;

            try
            {
                if (JwsEd25519Verifier.IsDetached(protectedHeader))
                {
                    // Caso: firma desacoplada (b64:false)
                    _logger.LogInformation("Firma desacoplada detectada. Generando payload canónico sin proof.");

                    var node = JsonNode.Parse(vc!.ToJsonString());
                    node!.AsObject().Remove("proof");
                    RemoveNulls(node);
                    node = SortJsonKeys(node); // orden determinístico independiente del campo order de Inji

                    _logger.LogInformation("Se ha removido el elemento proof de la VC para comparación canónica.");

                    var canonicalJson = JsonSerializer.Serialize(
                        node,
                        new JsonSerializerOptions
                        {
                            WriteIndented = false,
                            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                        });

                    _logger.LogInformation("Se ha serializado la VC sin proof para comparación canónica.");

                    var dumpPath = Path.Combine(_logPath, "Data", "last_payload_verified.json");
                    Directory.CreateDirectory(Path.GetDirectoryName(dumpPath)!);

                    _logger.LogInformation("Se grabará el payload canónico que se usará para comparación en la ruta de logs: {logPath}.", _logPath);

                    await File.WriteAllTextAsync(dumpPath, canonicalJson, Encoding.UTF8);

                    _logger.LogInformation("Payload canónico guardado en {Path}", dumpPath);

                    var payloadBytesDbg = Encoding.UTF8.GetBytes(canonicalJson);
                    _logger.LogInformation("PAYLOAD_HASH_VERIFICADOR: {Hash}", Convert.ToHexString(SHA256.HashData(payloadBytesDbg)));
                    _logger.LogInformation("PAYLOAD_LEN_VERIFICADOR: {Len}", payloadBytesDbg.Length);
                    _logger.LogInformation("PAYLOAD_PREFIX_VERIFICADOR: {Prefix}", canonicalJson[..Math.Min(300, canonicalJson.Length)]);

                    ok = JwsEd25519Verifier.VerifyDetachedJws(protectedHeader, canonicalJson, signature, key.PublicKey);

                    _logger.LogInformation("La verificación de la VC con la firma resultó: {ok}", ok.ToString());
                }
                else
                {
                    _logger.LogInformation("Firma compacta detectada.");
                    // Firma compacta normal (b64:true)
                    ok = JwsEd25519Verifier.VerifyCompactJws(jws, key.PublicKey);
                    _logger.LogInformation("La verificación de la VC con la firma resultó: {ok}", ok.ToString());
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante la verificación criptográfica del proof.jws.");
                return Fail("Error interno al verificar la firma de la VC.");
            }

            if (!ok)
            {
                _logger.LogWarning("Firma Ed25519 inválida en la VC JSON-LD | Issuer={Issuer}", issuer);
                return Fail("Firma inválida en la VC (proof.jws)");
            }

            _logger.LogInformation("Firma Ed25519 válida para issuer {Issuer}", issuer);
            checks.Add(new VerificationCheck { Name = "Firma de la VC", Passed = ok, Message = ok ? "OK" : "Inválida" });

            // 🔍 Verificación formal del estado (BitstringStatusList)
            _logger.LogInformation("Verificando estado en lista de revocación (BitstringStatusList).");
            var (validStatus, statusValue, purpose) = await VerifyCredentialStatusAsync(vc);

            checks.Add(new VerificationCheck
            {
                Name = "Estado en lista de revocación",
                Passed = validStatus,
                Message = validStatus ? "Activo" : $"Revocado ({statusValue})"
            });

            string? subject = TryExtractSubject(vc as JsonNode);
            _logger.LogInformation("Subject extraído: {Subject}", subject ?? "(no disponible)");

            var result = new VerificationResult
            {
                Valid = ok && validStatus,
                Reason = ok && validStatus ? "VC válida y activa" : "VC con errores o revocada",
                Issuer = issuer,
                Subject = subject,
                Status = statusValue,
                VcNode = vc,
                CheckedAt = DateTime.UtcNow,
                Checks = checks
            };

            _logger.LogInformation("🟩 Verificación JSON-LD completada | Valid={Valid} | Status={Status} | Issuer={Issuer}",
                result.Valid, statusValue, issuer);

            return result;
        }

        private static VerificationResult Fail(string reason) =>
            new VerificationResult { Valid = false, Reason = reason };

        private static string? TryExtractSubject(JsonNode? node)
        {
            if (node is null) return null;

            // Try common paths: vc.credentialSubject.numeroDocumento, vc.credentialSubject.id, sub claim, etc.
            var subject = node["credentialSubject"]?["numeroDocumento"]?.GetValue<string>()
                       ?? node["credentialSubject"]?["id"]?.GetValue<string>()
                       ?? node["sub"]?.GetValue<string>();

            // Also try your nested Titular object
            subject ??= node["credentialSubject"]?["titular"]?["numeroDocumento"]?.GetValue<string>();

            return subject;
        }

        private static JsonNode? SortJsonKeys(JsonNode? node)
        {
            if (node is JsonObject obj)
            {
                var sorted = new JsonObject();
                foreach (var kv in obj.OrderBy(k => k.Key, StringComparer.Ordinal))
                    sorted[kv.Key] = SortJsonKeys(kv.Value);
                return sorted;
            }
            if (node is JsonArray arr)
            {
                var sortedArr = new JsonArray();
                foreach (var item in arr)
                    sortedArr.Add(SortJsonKeys(item));
                return sortedArr;
            }
            return node?.DeepClone();
        }

        void RemoveNulls(JsonNode? node)
        {
            if (node is JsonObject obj)
            {
                // recopila las claves con valor null
                var keysToRemove = new List<string>();
                foreach (var kv in obj)
                {
                    if (kv.Value is null)
                        keysToRemove.Add(kv.Key);
                }
                foreach (var key in keysToRemove)
                    obj.Remove(key);

                // recursión sobre los valores restantes
                foreach (var kv in obj)
                    RemoveNulls(kv.Value);
            }
            else if (node is JsonArray arr)
            {
                foreach (var item in arr)
                    RemoveNulls(item);
            }
        }

        // ================================================================
        // NUEVA SECCIÓN: verificación contextual según tipo de entidad
        // ================================================================
        public async Task<VerificationResult> VerifyByProfileAsync(VerificationResult baseResult, string profile, JsonNode? fullVpNode = null)
        {
            _logger.LogInformation("Iniciando verificación contextual | Perfil={Profile} | BaseValid={Valid} | Issuer={Issuer}",
                profile, baseResult.Valid, baseResult.Issuer);

            // === 1. Validar issuer antes de continuar ===
            var issuer = baseResult.Issuer;
            if (string.IsNullOrWhiteSpace(issuer)) {
                _logger.LogWarning("Issuer faltante en credencial | Perfil={Profile}", profile);
                return Fail("Issuer faltante en la credencial.");
            }

            // === 2. Preparar resultado extendido ===
            var result = baseResult.Clone();
            result.Profile = profile.ToLower();
            result.CheckedAt = DateTime.UtcNow;

            try 
            {
                // NUEVO: usa la VC verificada si existe (prioridad sobre el vp_node)
                var sourceNode = baseResult.VcNode ?? fullVpNode;
                var data = result.Data ?? ExtractBasicData(sourceNode);
                result.Data = data;

                //  === 3. Checks base (cripto + confianza issuer) ===
                result.Checks.Add(new VerificationCheck
                {
                    Name = "Firma criptográfica",
                    Passed = baseResult.Valid,
                    Message = baseResult.Valid ? "Firma Ed25519 válida" : "Falla en la validación de la firma"
                });

                result.Checks.Add(new VerificationCheck
                {
                    Name = "Issuer confiable",
                    Passed = _trust.IsTrusted(issuer),
                    Message = baseResult.Issuer ?? "Issuer desconocido"
                });

                // === 4. Mantener información de estado (revocación) ===
                result.Checks.Add(new VerificationCheck
                {
                    Name = "Estado de la credencial",
                    Passed = string.Equals(baseResult.Status, "active", StringComparison.OrdinalIgnoreCase),
                    Message = baseResult.Status ?? "Estado desconocido"
                });

                // // === 5. Aplicar reglas de perfil específico ===
                switch (result.Profile)
                {
                    case "empresa":
                        _logger.LogInformation("Aplicando reglas del perfil EMPRESA");
                        ApplyEmpresaChecks(result, data);
                        break;
                    case "instituto":
                        _logger.LogInformation("Aplicando reglas del perfil INSTITUTO");
                        ApplyInstitutoChecks(result, data);
                        break;
                    case "evento":
                        _logger.LogInformation("Aplicando reglas del perfil EVENTO");
                        await ApplyEventoChecksAsync(result, data);
                        break;
                    case "entidad-publica":
                        _logger.LogInformation("Aplicando reglas del perfil ENTIDAD PÚBLICA");
                        ApplyEntidadPublicaChecks(result, data);
                        break;
                    default:
                        _logger.LogWarning("Perfil de verificación desconocido: {Profile}", profile);
                        result.Valid = false;
                        result.Reason = "Perfil de verificación desconocido";
                        break;
                }

                // === 6. Consolidar resultado ===
                if (!baseResult.Valid)
                {
                    _logger.LogWarning("Verificación base inválida | Perfil={Profile} | Reason={Reason}",
                        profile, baseResult.Reason);
                    result.Valid = false;
                    result.Reason = "Falla en validación criptográfica o estado revocado";
                }

                var gradoInfo = result.Summary != null && result.Summary.TryGetValue("UltimoGrado", out var g)
                    ? $" (grado={g}, situacion={result.Summary.GetValueOrDefault("UltimaSituacion", "—")})"
                    : "";
                _logger.LogInformation("Verificación contextual finalizada | Perfil={Profile} | Valid={Valid} | Reason={Reason}{GradoInfo}",
                    result.Profile, result.Valid, result.Reason, gradoInfo);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en verificación contextual | Perfil={Profile} | Issuer={Issuer}",
                    profile, issuer);
                return Fail($"Error en verificación contextual: {ex.Message}");
            }
        }

        private void ApplyEmpresaChecks(VerificationResult result, Dictionary<string, object> data)
        {
            result.Context = "Validación empresarial (Terminó educación básica regular)";
            var checks = result.Checks;

            // 1️) Modalidad EBR
            string? modalidad = data.TryGetValue("modalidad", out var mod) ? mod?.ToString() : null;
            bool modalidadOk = string.Equals(modalidad, "EBR", StringComparison.OrdinalIgnoreCase);

            checks.Add(new VerificationCheck
            {
                Name = "Modalidad de estudios",
                Passed = modalidadOk,
                Message = modalidadOk ? "El titular culminó estudios en modalidad EBR" : "La modalidad no es EBR"
            });

            // 2️) Último grado aprobado = 5
            bool aprobado5to = false;
            int ultimoGrado = 0;
            string ultimaSituacion = "—";
            if (data.TryGetValue("gradosConcluidos", out var gradosObj) && gradosObj is JsonArray grados)
            {
                var ultimo = grados
                    .Select(g => new
                    {
                        grado = g?["grado"]?.GetValue<int>() ?? 0,
                        anio = g?["anio"]?.GetValue<int>() ?? 0,
                        situacion = g?["situacionFinal"]?.GetValue<string>() ?? ""
                    })
                    .OrderByDescending(x => x.anio)
                    .FirstOrDefault();

                if (ultimo != null)
                {
                    ultimoGrado = ultimo.grado;
                    ultimaSituacion = ultimo.situacion;
                    if (ultimo.grado == 5 &&
                        string.Equals(ultimo.situacion, "APROBADO", StringComparison.OrdinalIgnoreCase))
                        aprobado5to = true;
                }
            }

            checks.Add(new VerificationCheck
            {
                Name = "Aprobación de 5.º grado EBR",
                Passed = aprobado5to,
                Message = aprobado5to ? "5.º de secundaria aprobado" : "No se encontró 5.º aprobado"
            });

            // 3️⃣ Datos personales básicos
            string? nombres = data.TryGetValue("nombres", out var nom) ? nom?.ToString() : null;
            string? apellidos = data.TryGetValue("apellidos", out var ape) ? ape?.ToString() : null;
            string? documento = data.TryGetValue("numeroDocumento", out var doc) ? doc?.ToString() : null;
            bool datosPersonalesOk = !string.IsNullOrEmpty(nombres) && !string.IsNullOrEmpty(apellidos) && !string.IsNullOrEmpty(documento);

            checks.Add(new VerificationCheck
            {
                Name = "Datos personales presentes",
                Passed = datosPersonalesOk,
                Message = datosPersonalesOk ? "Nombres, apellidos y numero de documento detectados" : "Faltan datos personales"
            });

            // Resultado consolidado
            result.Valid = result.Valid && modalidadOk && aprobado5to && datosPersonalesOk;
            result.Reason = result.Valid
                ? "Cumple requisitos de EBR completo"
                : "No cumple los criterios de finalización de EBR";

            result.Summary = new Dictionary<string, object>
            {
                ["Modalidad"] = modalidad ?? "—",
                ["UltimoGrado"] = ultimoGrado,
                ["UltimaSituacion"] = ultimaSituacion,
                ["5.º aprobado"] = aprobado5to ? "Sí" : "No",
                ["Documento"] = documento ?? "—",
                ["Nombres"] = nombres ?? "—"
            };
        }

        private void ApplyInstitutoChecks(VerificationResult result, Dictionary<string, object> data)
        {
            result.Context = "Validación académica (ingreso a instituto artístico con beca)";
            var checks = result.Checks;

            bool todasArteExcelentes = true;
            int totalArteNotas = 0;
            int notasValidas = 0;

            // Busca en gradosConcluidos[*].notas[*] calificaciones AD o A en Arte
            if (data.TryGetValue("gradosConcluidos", out var gradosObj) && gradosObj is JsonArray grados)
            {
                foreach (var g in grados)
                {
                    var notas = g?["notas"] as JsonArray;
                    if (notas == null) continue;

                    foreach (var n in notas)
                    {
                        var area = n?["area"]?.GetValue<string>() ?? n?["competencia"]?.GetValue<string>();
                        var calif = n?["calificacion"]?.GetValue<string>();

                        if (string.IsNullOrEmpty(area) || !area.Contains("Arte", StringComparison.OrdinalIgnoreCase))
                            continue;

                        totalArteNotas++;

                        if (calif == "AD" || calif == "A")
                        {
                            notasValidas++;
                        }
                        else
                        {
                            todasArteExcelentes = false;
                        }
                    }
                }
            }

            // ✅ Check principal
            bool aprobadoParaBeca = todasArteExcelentes && totalArteNotas > 0;

            checks.Add(new VerificationCheck
            {
                Name = "Calificaciones en Arte y Cultura",
                Passed = aprobadoParaBeca,
                Message = aprobadoParaBeca
                    ? "Todas las calificaciones en Arte son AD/A"
                    : "Se encontró al menos una calificación menor a A en Arte"
            });

            // Resumen general
            result.Valid = result.Valid && aprobadoParaBeca;
            result.Reason = result.Valid
                ? "Cumple todos los requisitos para beca artística"
                : "No cumple desempeño artístico en todas las áreas de Arte";

            result.Summary = new Dictionary<string, object>
            {
                ["Notas de Arte evaluadas"] = totalArteNotas,
                ["AD/A detectadas"] = notasValidas,
                ["Todas AD/A"] = aprobadoParaBeca ? "Sí" : "No"
            };
        }

        private async Task ApplyEventoChecksAsync(VerificationResult result, Dictionary<string, object> data)
        {
            result.Context = "Control de acceso a evento (lista de invitados)";

            var dni       = data.TryGetValue("numeroDocumento", out var d) ? d?.ToString()?.Trim() : null;
            var nombres   = data.TryGetValue("nombres",          out var n) ? n?.ToString()?.Trim() : null;
            var apellidos = data.TryGetValue("apellidos",        out var a) ? a?.ToString()?.Trim() : null;

            // 1. Datos presentes
            bool datosOk = !string.IsNullOrEmpty(dni) && !string.IsNullOrEmpty(nombres);
            result.Checks.Add(new VerificationCheck
            {
                Name    = "Datos del titular",
                Passed  = datosOk,
                Message = datosOk ? "Nombres y DNI presentes en la credencial" : "Faltan datos del titular"
            });

            if (!datosOk)
            {
                result.Valid   = false;
                result.Reason  = "La credencial no contiene los datos requeridos";
                result.Summary = new Dictionary<string, object> { ["dni"] = dni ?? "—" };
                return;
            }

            // 2. Está en la lista de invitados
            bool esInvitado = _attendees.EsInvitado(dni!);
            result.Checks.Add(new VerificationCheck
            {
                Name    = "Lista de invitados",
                Passed  = esInvitado,
                Message = esInvitado ? "Participante en la lista del evento" : "El DNI no figura en la lista de invitados"
            });

            if (!esInvitado)
            {
                result.Valid   = false;
                result.Reason  = "El participante no figura en la lista de invitados del evento";
                result.Summary = new Dictionary<string, object> { ["DNI"] = dni! };
                return;
            }

            // 3. Registrar asistencia en DB
            var (yaRegistrado, registro) = await _attendees.RegistrarAsistenciaAsync(dni!, nombres!, apellidos ?? "");
            var horaAcceso = (registro.PrimerAccesoEn ?? DateTime.UtcNow).ToLocalTime();

            result.Checks.Add(new VerificationCheck
            {
                Name    = "Registro de asistencia",
                Passed  = true,
                Message = yaRegistrado
                    ? $"Asistencia ya registrada el {horaAcceso:dd/MM/yyyy HH:mm} (intento #{registro.IntentosAcceso})"
                    : "Asistencia registrada exitosamente"
            });

            result.Valid  = true;
            result.Reason = yaRegistrado
                ? "Participante verificado (asistencia ya registrada previamente)"
                : "Participante verificado y asistencia registrada";
            result.Summary = new Dictionary<string, object>
            {
                ["Nombres"]      = nombres!,
                ["DNI"]          = dni!,
                ["YaRegistrado"] = yaRegistrado,
                ["RegistradoEn"] = horaAcceso.ToString("dd/MM/yyyy HH:mm")
            };
        }

        private void ApplyEntidadPublicaChecks(VerificationResult result, Dictionary<string, object> data)
        {
            result.Context = "Validación para capacitación de egresados recientes";
            var checks = result.Checks;

            // 1️) Determinar último año y grado cursado
            int ultimoAnio = 0;
            int ultimoGrado = 0;
            string? modalidad = data.TryGetValue("modalidad", out var mod) ? mod?.ToString() : null;
            string? nivel = data.TryGetValue("nivel", out var niv) ? niv?.ToString() : null;

            if (data.TryGetValue("gradosConcluidos", out var gradosObj) && gradosObj is JsonArray grados)
            {
                foreach (var g in grados)
                {
                    var anio = g?["anio"]?.GetValue<int>() ?? 0;
                    if (anio > ultimoAnio)
                    {
                        ultimoAnio = anio;
                        ultimoGrado = g?["grado"]?.GetValue<int>() ?? 0;
                    }
                }
            }

            // 2️) Verificar que esté cursando último año en 2025
            bool cursaUltimo = false;
            if (ultimoAnio == 2024)
            {
                // Cursa el año siguiente (2025)
                if ((modalidad == "EBR" && ultimoGrado == 4) ||
                    (modalidad == "EBA" && ultimoGrado == 8))
                {
                    cursaUltimo = true;
                }
            }

            checks.Add(new VerificationCheck
            {
                Name = "Condición de estudiante en último año (2025)",
                Passed = cursaUltimo,
                Message = cursaUltimo
                    ? "Cursa su último año (5.º EBR o 9.º EBA) en 2025"
                    : "No se encontró condición de cursante en último año"
            });

            result.Valid = result.Valid && cursaUltimo;
            result.Reason = result.Valid
                ? "Elegible para programas de capacitación a egresados"
                : "No cumple condición de cursar último año";

            result.Summary = new Dictionary<string, object>
            {
                ["Modalidad"] = modalidad ?? "—",
                ["Último grado aprobado"] = ultimoGrado,
                ["Año lectivo más reciente"] = ultimoAnio,
                ["Cursa último año 2025"] = cursaUltimo ? "Sí" : "No"
            };
        }

        private static Dictionary<string, object> ExtractBasicData(JsonNode? vc)
        {
            var dict = new Dictionary<string, object>();
            if (vc == null) return dict;

            void Add(string key, string? value)
            {
                if (!string.IsNullOrEmpty(value))
                    dict[key] = value;
            }

            // Basic string fields
            Add("nombres", vc["credentialSubject"]?["titular"]?["nombres"]?.GetValue<string>());
            Add("apellidos", vc["credentialSubject"]?["titular"]?["apellidos"]?.GetValue<string>());
            Add("numeroDocumento", vc["credentialSubject"]?["titular"]?["numeroDocumento"]?.GetValue<string>());
            Add("nivel", vc["credentialSubject"]?["nivel"]?.GetValue<string>());
            Add("modalidad", vc["credentialSubject"]?["modalidad"]?.GetValue<string>());
            Add("schema", vc["credentialSchema"]?["id"]?.GetValue<string>());

            // NEW: include full array of gradosConcluidos (as JsonArray)
            var grados = vc["credentialSubject"]?["gradosConcluidos"] as JsonArray;
            if (grados != null)
            {
                dict["gradosConcluidos"] = grados;
            }

            return dict;
        }

        private async Task<(bool valid, string status, string purpose)> VerifyCredentialStatusAsync (JsonNode? vcNode)
        {
            _logger.LogInformation("Iniciando verificación en lista de revocación | vcNode={vcNode}", vcNode);
            try
            {
                // === 1. Extraer datos básicos ===
                if (vcNode == null)
                {
                    _logger.LogError("El valor del parametro vcNode es nulo.");
                    return (false, "invalid", "none");
                }
                

                var credentialStatus = vcNode?["credentialStatus"];
                if (credentialStatus == null)
                {
                    _logger.LogWarning("La VC no conitiene un elemento credentialStatus.");
                    return (true, "no-status", "none");
                }

                var statusUrl = credentialStatus?["statusListCredential"]?.GetValue<string>();
                var index = credentialStatus?["statusListIndex"]?.ToString();
                var statusPurpose = credentialStatus?["statusPurpose"]?.GetValue<string>();

                _logger.LogInformation("Se obtiene los valores de la lista de revocacion contenidas en la VC | statusUrl={statusUrl} | index={index} | statusPurpose={statusPurpose}", statusUrl, index, statusPurpose);

                if (string.IsNullOrEmpty(statusUrl) || string.IsNullOrEmpty(index))
                {
                    _logger.LogWarning("Los datos de la lista de revocacion de credenciales no están completos.");
                    return (false, "missing_fields", statusPurpose ?? "unknown");
                }

                // === 2. Descargar la StatusListCredential ===
                _logger.LogInformation("Se hará la petición para obtener la lista de revocacion de credenciales.");

                JsonDocument? doc = null;
                string? jsonText = null;
                try 
                {
                    using var http = new HttpClient();
                    jsonText = await http.GetStringAsync(statusUrl);
                    doc = JsonDocument.Parse(jsonText);
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogError(ex, "No se pudo obtener la StatusList desde la URL: {StatusUrl}", statusUrl);
                    return (false, "statuslist_no_responde", statusPurpose ?? "desconocido");
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "La respuesta de la StatusList no es un JSON válido: {StatusUrl}", statusUrl);
                    return (false, "statuslist_json_invalido", statusPurpose ?? "desconocido");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error inesperado durante la verificación de la StatusList: {StatusUrl}", statusUrl);
                    return (false, "statuslist_error_interno", statusPurpose ?? "desconocido");
                }

                _logger.LogInformation("Se realizó la petición para obtener la lista de revocacion de credenciales. | jsonText={jsonText}", jsonText);

                // === 3. Extraer campos principales ===
                if (!TryGetCaseInsensitive(doc.RootElement, "proof", out var proofElem) || proofElem.ValueKind != JsonValueKind.Object)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta proof en la lista de estado.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta proof en la lista de estado.");
                }

                if (!TryGetCaseInsensitive(proofElem, "jws", out var jwsEl))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta jws en la prueba de la lista.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta jws en la prueba de la lista.");
                }

                if (!TryGetCaseInsensitive(proofElem, "verificationMethod", out var vmEl))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta verificationMethod en la prueba de la lista.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta verificationMethod en la prueba de la lista.");
                }

                var jws = jwsEl.GetString();
                var verificationMethod = vmEl.GetString();

                if (!TryGetCaseInsensitive(doc.RootElement, "issuer", out var issEl))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta issuer en la lista de estado.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta issuer en la lista de estado.");
                }
                
                var issuer = issEl.GetString();

                if (!TryGetCaseInsensitive(doc.RootElement, "credentialSubject", out var csEl) || csEl.ValueKind != JsonValueKind.Object)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta credentialSubject en la lista de estado.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta credentialSubject en la lista de estado.");
                }

                if (!TryGetCaseInsensitive(csEl, "statusPurpose", out var spEl))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta statusPurpose en credentialSubject.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta statusPurpose en credentialSubject.");
                }

                if (!TryGetCaseInsensitive(csEl, "encodedList", out var encEl))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Falta encodedList en credentialSubject.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Falta encodedList en credentialSubject.");
                }

                var listPurpose = spEl.GetString();
                var encodedList = encEl.GetString();

                // === 4. Validar firma del StatusListCredential ===
                _logger.LogInformation("Se realizará la petición para resolver la llave criptografica de la lista de revocacion de credenciales. | jsonText={jsonText} | verificationMethod={verificationMethod}", jsonText, verificationMethod);
                var key = await _did.ResolveKeyAsync(issuer!, verificationMethod!);
                _logger.LogInformation("Se resuelve la petición para resolver la llave criptografica de la lista de revocacion de credenciales. | key={key}", key.ToString());

                if (key == null || key.Crv != "Ed25519")
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: No se pudo resolver clave Ed25519 del issuer.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: No se pudo resolver clave Ed25519 del issuer.");
                }

                // Detectar si la firma usa formato detached (b64=false)
                var parts = jws!.Split('.');
                if (parts.Length != 3)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Formato JWS inválido en lista de estado. (partes: {numPartes})", parts.Length);
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Formato JWS inválido en lista de estado.");
                }
                
                var protectedHeader = parts[0];
                var signature = parts[2];
                bool ok;
                _logger.LogInformation("Se leyendo las partes del jws de la lista. | protectedHeader={protectedHeader} | signature={signature}", protectedHeader, signature);

                _logger.LogInformation("Se evaluará si la firma del JWS de la lista está desacoplada.");
                if (JwsEd25519Verifier.IsDetached(protectedHeader))
                {
                    _logger.LogInformation("La firma del JWS de la lista está desacoplada.");
                    // Firma desacoplada → payload = contenido JSON sin codificar
                    // 1) Quitar temporalmente el campo "proof" del JSON antes de verificar la firma
                    _logger.LogInformation("Se quitará el elemento proof del JWS antes de verificar la firma.");
                    // Quitar proof y ordenar claves (mismo tratamiento que el emisor)
                    var slNode = JsonNode.Parse(jsonText)!.AsObject();
                    slNode.Remove("proof");
                    var slSorted = SortJsonKeys(slNode);
                    var payloadWithoutProof = JsonSerializer.Serialize(slSorted, new JsonSerializerOptions
                    {
                        WriteIndented = false,
                        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                    });
                    _logger.LogInformation("Se genera un string del payload limpio sin proof. | payloadWithoutProof={payloadWithoutProof}", payloadWithoutProof);

                    // 3️) Guardar en disco para comparar
                    var path = Path.Combine(_logPath, "Data", "statuslist-payload-verificador-sinproof.json");
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    await File.WriteAllTextAsync(path, payloadWithoutProof);

                    _logger.LogInformation("Se generó una copia del payload limpio sin proof en la ruta: {path}", path);

                    var payloadBytes = Encoding.UTF8.GetBytes(payloadWithoutProof);

                    _logger.LogInformation("PAYLOAD_HASH_STATUSLIST_VERIFICADOR: {Hash}", Convert.ToHexString(SHA256.HashData(payloadBytes)));
                    _logger.LogInformation("PAYLOAD_LEN_STATUSLIST_VERIFICADOR: {Len}", payloadBytes.Length);
                    _logger.LogInformation("PAYLOAD_PREFIX_STATUSLIST_VERIFICADOR: {Prefix}", payloadWithoutProof[..Math.Min(200, payloadWithoutProof.Length)]);

                    _logger.LogInformation("Se evaluará el payload canonico de la lista de estados. | signature={signature} | key.PublicKey={PublicKey}", signature, key.PublicKey);
                    ok = JwsEd25519Verifier.VerifyDetachedJws(protectedHeader, Encoding.UTF8.GetString(payloadBytes), signature, key.PublicKey);
                    _logger.LogInformation("Se evaluó el payload canonico de la lista de estados. | resultado={ok}", ok.ToString());
                }
                else
                {
                    _logger.LogInformation("La firma del JWS de la lista está embebida.");
                    _logger.LogInformation("Se evaluará el jws de la lista de estados. | jws={jws} | key.PublicKey={PublicKey}", jws, key.PublicKey);
                    // Firma embebida (b64=true)
                    ok = JwsEd25519Verifier.VerifyCompactJws(jws!, key.PublicKey);
                    _logger.LogInformation("Se evaluó el jws compacto con firma embebida de la lista de estados. | resultado={ok}", ok.ToString());
                }

                if (!ok)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: La firma de la lista de estado es inválida.)");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: La firma de la lista de estado es inválida.");
                }

                // === 5. Validar issuer coincidente con la VC ===
                var vcIssuer = vcNode?["issuer"]?.GetValue<string>();
                if (!string.Equals(issuer, vcIssuer, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Issuer no coincide entre VC y StatusListCredential. | vcIssuer={vcIssuer} | issuer={issuer}.", vcIssuer, issuer);
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: issuer mismatch entre VC y StatusListCredential.");
                }
                _logger.LogInformation("Se validó correctamente el emisor de la VC vs el emisor de la lista de estados.");

                // === 6. Descomprimir encodedList ===
                //var compressed = Convert.FromBase64String(encodedList!);
                string encoded = encodedList!
                    .Replace('-', '+')
                    .Replace('_', '/');

                _logger.LogInformation("Se procesa la lista de estados. | encoded={encoded}", encoded); 

                switch (encoded.Length % 4)
                {
                    case 2: encoded += "=="; break;
                    case 3: encoded += "="; break;
                }

                byte[] compressed;
                try
                {
                    compressed = Convert.FromBase64String(encoded);
                }
                catch (FormatException)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: encodedList no está en formato Base64 válido.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: encodedList no está en formato Base64 válido.");
                }

                using var gzip = new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress);
                using var ms = new MemoryStream();
                await gzip.CopyToAsync(ms);
                var bitstring = ms.ToArray();

                // === 7. Verificar bit ===
                var bitIndex = int.Parse(index!);
                var byteIndex = bitIndex / 8;
                var bitOffset = bitIndex % 8;

                if (byteIndex >= bitstring.Length)
                {
                    _logger.LogError("STATUS_VERIFICATION_ERROR: Index fuera de rango en encodedList.");
                    throw new InvalidOperationException("STATUS_VERIFICATION_ERROR: Index fuera de rango en encodedList.");
                }
                    

                bool revoked = (bitstring[byteIndex] & (1 << (7 - bitOffset))) != 0;
                _logger.LogInformation("Se obtiene el bit de revocacion especifico de la credencial a evaluar. | revoked={revoked}", revoked.ToString());

                return (!revoked, revoked ? "revoked" : "active", listPurpose ?? "revocation");
            }
            catch (Exception ex)
            {
                _logger.LogError("Excepcion No Controlada: {Message}.", ex.Message);
                return (false, $"exception:{ex.Message}", "unknown");
            }
        }

        // helper local
        static bool TryGetCaseInsensitive(System.Text.Json.JsonElement obj, string name, out System.Text.Json.JsonElement value)
        {
            if (obj.TryGetProperty(name, out value)) return true;                 // camelCase
            var pascal = char.ToUpperInvariant(name[0]) + name[1..];
            return obj.TryGetProperty(pascal, out value);                          // PascalCase
        }
    }
}
