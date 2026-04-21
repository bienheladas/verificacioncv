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

            var portalBase = _config.PortalBaseUrl.TrimEnd('/');
            var logoUrl = $"{portalBase}/assets/empresa-logo.svg";
            var (clientName, clientContact) = profile.ToLower() switch
            {
                "empresa"         => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos"),
                "instituto"       => ("Instituto Nacional de Arte del Perú", "Oficina de Admisión"),
                "entidad-publica" => ("Min. de Trabajo y Promoción del Empleo", "Dir. de Capacitación"),
                _                 => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos")
            };
            var clientMetadata = JsonSerializer.Serialize(new
            {
                client_name = clientName,
                logo_uri    = logoUrl,
                contacts    = new[] { clientContact }
            });

            var qrUri =
                $"openid4vp://authorize?" +
                $"client_id={Encode(callbackUrl)}" +
                $"&client_id_scheme=redirect_uri" +
                $"&response_type=vp_token" +
                $"&response_mode=direct_post" +
                $"&response_uri={Encode(callbackUrl)}" +
                $"&nonce={Encode(session.Nonce)}" +
                $"&state={Encode(session.State)}" +
                $"&client_metadata={Encode(clientMetadata)}" +
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
                    new { path = new[] { "$.type[*]" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                "instituto" => new object[]
                {
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].notas[*].area" }, filter = new { type = "string", pattern = "ARTE Y CULTURA" } },
                    new { path = new[] { "$.credentialSubject.titular.numeroDocumento" } },
                    new { path = new[] { "$.credentialSubject.titular.nombres" } },
                    new { path = new[] { "$.type[*]" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                "entidad-publica" => new object[]
                {
                    new { path = new[] { "$.credentialSubject.modalidad" } },
                    new { path = new[] { "$.credentialSubject.nivel" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" } },
                    new { path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" } },
                    new { path = new[] { "$.type[*]" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                },
                _ => new object[]
                {
                    new { path = new[] { "$.type[*]" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
                }
            };

            var format = new
            {
                ldp_vc = new
                {
                    proof_type = new[] { "JsonWebSignature2020" }
                }
            };

            return new
            {
                id = "pd",
                format,
                input_descriptors = new[]
                {
                    new
                    {
                        id = "vc",
                        constraints = new { fields }
                    }
                }
            };
        }
    }
}
