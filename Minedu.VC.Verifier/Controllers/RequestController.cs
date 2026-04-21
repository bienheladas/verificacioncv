using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;
using Minedu.VC.Verifier.Services;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("verifier/request")]
    [ApiController]
    public class RequestController : ControllerBase
    {
        private readonly SessionService _sessions;
        private readonly VerifierConfig _config;
        private readonly VerifierJwtService _jwt;
        private readonly ILogger<RequestController> _logger;

        public RequestController(SessionService sessions, IOptions<VerifierConfig> cfg, VerifierJwtService jwt, ILogger<RequestController> logger)
        {
            _sessions = sessions;
            _config = cfg.Value;
            _jwt = jwt;
            _logger = logger;
        }

        [HttpGet("{sessionId}")]
        public IActionResult GetAuthRequest(string sessionId)
        {
            _logger.LogInformation("Empieza Request URI endpoint!");

            var s = _sessions.GetSession(sessionId);
            _logger.LogInformation("sessionId={sessionId}", sessionId);

            if (s is null)
            {
                _logger.LogError("Finaliza endpoint, SessionId es nulo.");
                return NotFound();
            } 

            var callbackUrl = $"{_config.BaseApiUrl.TrimEnd('/')}{_config.CallbackPath}/{s.SessionId}";
            var schemaUrl = $"{_config.SchemaBaseUrl.TrimEnd('/')}/schema.json";
            var profile = s.Profile?.ToLower() ?? "-";

            _logger.LogInformation("callbackUrl={callbackUrl} | schemaUrl={schemaUrl} | profile={profile}", callbackUrl, schemaUrl, profile);

            // --- Definiciones dinámicas según perfil ---
            object[] fields;

            // Solo pattern sin type: Inji falla cuando typeof valor !== type (ej. number/object ≠ "string").
            // La validación real de valores se hace server-side en VerificationService.
            var any = new { pattern = ".*" };
            var vcType = new { type = "string", pattern = "CertificadoEstudios" };

            switch (profile)
            {
                case "empresa":
                    fields = new object[]
                    {
                        new { path = new[] { "$.credentialSubject.modalidad" },                          filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos" },                   filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" },          filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" },           filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" }, filter = any },
                        new { path = new[] { "$.credentialSubject.titular.numeroDocumento" },            filter = any },
                        new { path = new[] { "$.credentialSubject.titular.nombres" },                   filter = any },
                        new { path = new[] { "$.type[*]" },                                             filter = vcType }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil empresa.");
                    break;

                case "instituto":
                    fields = new object[]
                    {
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].notas[*].area" }, filter = any },
                        new { path = new[] { "$.credentialSubject.titular.numeroDocumento" },            filter = any },
                        new { path = new[] { "$.credentialSubject.titular.nombres" },                   filter = any },
                        new { path = new[] { "$.type[*]" },                                             filter = vcType }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil instituto.");
                    break;

                case "entidad-publica":
                    fields = new object[]
                    {
                        new { path = new[] { "$.credentialSubject.modalidad" },                          filter = any },
                        new { path = new[] { "$.credentialSubject.nivel" },                              filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos" },                   filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" },          filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" },           filter = any },
                        new { path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" }, filter = any },
                        new { path = new[] { "$.type[*]" },                                             filter = vcType }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil entidad-publica.");
                    break;

                default:
                    fields = new object[]
                    {
                        new { path = new[] { "$.type[*]" }, filter = vcType }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación por defecto.");
                    break;
            }

            var portalBase = _config.PortalBaseUrl.TrimEnd('/');
            var (clientName, clientContact) = profile switch
            {
                "empresa"         => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos"),
                "instituto"       => ("Instituto Nacional de Arte del Perú", "Oficina de Admisión"),
                "entidad-publica" => ("Min. de Trabajo y Promoción del Empleo", "Dir. de Capacitación"),
                _                 => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos")
            };

            var claims = new
            {
                iss              = _config.Did,
                client_id        = _config.Did,
                client_id_scheme = "did",
                response_type    = "vp_token",
                response_mode    = "direct_post",
                response_uri     = callbackUrl,
                state            = s.State,
                nonce            = s.Nonce,
                client_metadata  = new
                {
                    client_name = clientName,
                    logo_uri    = $"{portalBase}/assets/empresa-logo.svg",
                    contacts    = new[] { clientContact },
                    vp_formats  = new
                    {
                        ldp_vp = new { proof_type = new[] { "JsonWebSignature2020" } }
                    }
                },
                presentation_definition = new
                {
                    id = "pd",
                    format = new { ldp_vc = new { proof_type = new[] { "JsonWebSignature2020" } } },
                    input_descriptors = new[] {
                        new { id = "vc", constraints = new { fields } }
                    }
                }
            };

            var jwt = _jwt.CreateRequestJwt(claims);
            _logger.LogInformation("OID4VP Request JWT generado para sessionId={SessionId}", sessionId);

            return Content(jwt, "application/oauth-authz-req+jwt");
        }
    }
}
