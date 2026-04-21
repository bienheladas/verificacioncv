using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;
using Minedu.VC.Verifier.Services;
using System.Text.Json;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("verifier/sessions")]
    [ApiController]
    public class SessionsController : ControllerBase
    {
        private readonly SessionService _sessionService;
        private readonly VerifierConfig _config;
        private readonly ILogger<SessionsController> _logger;

        public SessionsController(SessionService sessionService,
                                  IOptions<VerifierConfig> config,
                                  ILogger<SessionsController> logger)
        {
            _sessionService = sessionService;
            _config = config.Value;
            _logger = logger;
        }

        [HttpPost]
        public IActionResult CreateSession([FromQuery] string profile = "entidad-publica")
        {
            _logger.LogInformation("Empieza CreateSession | profile={Profile}", profile);

            var session = _sessionService.CreateSession(profile);
            var callbackUrl = $"{_config.BaseApiUrl.TrimEnd('/')}{_config.CallbackPath}/{session.SessionId}";
            var schemaUrl = $"{_config.SchemaBaseUrl.TrimEnd('/')}/schema.json";

            _logger.LogInformation("callbackUrl={CallbackUrl}", callbackUrl);

            string Encode(string v) => Uri.EscapeDataString(v);

            var presentationDefinition = BuildPresentationDefinition(profile, schemaUrl);
            var pdJson = JsonSerializer.Serialize(presentationDefinition);

            var qrUri =
                $"openid4vp://authorize?" +
                $"client_id={Encode(callbackUrl)}" +
                $"&client_id_scheme=redirect_uri" +
                $"&response_type=vp_token" +
                $"&response_mode=direct_post" +
                $"&response_uri={Encode(callbackUrl)}" +
                $"&nonce={Encode(session.Nonce)}" +
                $"&state={Encode(session.State)}" +
                $"&presentation_definition={Encode(pdJson)}";

            session.QrUri = qrUri;
            _logger.LogInformation("qr_uri generado | SessionId={SessionId}", session.SessionId);

            return Ok(new
            {
                session_id = session.SessionId,
                profile,
                qr_uri = qrUri
            });
        }

        [HttpGet("{sessionId}")]
        public IActionResult GetSession(string sessionId)
        {
            var session = _sessionService.GetSession(sessionId);
            if (session is null) return NotFound();
            return Ok(new
            {
                session_id = session.SessionId,
                profile = session.Profile,
                qr_uri = session.QrUri
            });
        }

        private object BuildPresentationDefinition(string profile, string schemaUrl)
        {
            object[] fields = profile.ToLower() switch
            {
                "empresa" => new object[]
                {
                    new { path = new[] { "$.credentialSubject.modalidad" }, filter = new { type = "string" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos" }, filter = new { type = "array" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" }, filter = new { type = "integer" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" }, filter = new { type = "integer" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" }, filter = new { type = "string" } },
                    new { path = new[] { "$.credentialSubject.titular.numeroDocumento" }, filter = new { type = "string" } },
                    new { path = new[] { "$.credentialSubject.titular.nombres" }, filter = new { type = "string" } },
                    new { path = new[] { "$.type" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                "instituto" => new object[]
                {
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].notas[*].area" }, filter = new { type = "string", pattern = "ARTE Y CULTURA" } },
                    new { path = new[] { "$.credentialSubject.titular.numeroDocumento" }, filter = new { type = "string", minLength = 8 } },
                    new { path = new[] { "$.credentialSubject.titular.nombres" }, filter = new { type = "string", minLength = 2 } },
                    new { path = new[] { "$.type" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                "entidad-publica" => new object[]
                {
                    new { path = new[] { "$.credentialSubject.modalidad" }, filter = new { type = "string" } },
                    new { path = new[] { "$.credentialSubject.nivel" }, filter = new { type = "string" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos" }, filter = new { type = "array" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" }, filter = new { type = "integer" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" }, filter = new { type = "integer" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" }, filter = new { type = "string" } },
                    new { path = new[] { "$.type" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                _ => new object[]
                {
                    new { path = new[] { "$.type" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                }
            };

            return new
            {
                id = $"pd-{profile.ToLower()}",
                name = "Validación de Certificado de Estudios",
                purpose = "Verificar autenticidad, integridad y condiciones de negocio según perfil",
                input_descriptors = new[]
                {
                    new
                    {
                        id = $"vc-{profile.ToLower()}",
                        schema = new[] { schemaUrl },
                        constraints = new { fields }
                    }
                }
            };
        }
    }
}
