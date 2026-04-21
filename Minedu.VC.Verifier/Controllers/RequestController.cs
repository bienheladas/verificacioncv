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
        private readonly ILogger<RequestController> _logger;

        public RequestController(SessionService sessions, IOptions<VerifierConfig> cfg, ILogger<RequestController> logger)
        {
            _sessions = sessions;
            _config = cfg.Value;
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

            switch (profile)
            {
                // EMPRESA → verificar que terminó 5to grado de secundaria (EBR)
                case "empresa":
                    fields = new object[] 
                    {
                        new {
                            path = new[] { "$.credentialSubject.modalidad" },
                            filter = new { type = "string"}
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos" },
                            filter = new { type = "array" }
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" },
                            filter = new { type = "integer"}
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" },
                            filter = new { type = "integer" }
                        },
                        // Situación final APROBADO
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" },
                            filter = new { type = "string"}
                        },
                        // Datos personales mínimos
                        new {
                            path = new[] { "$.credentialSubject.titular.numeroDocumento" },
                            filter = new { type = "string"}
                        },
                        new {
                            path = new[] { "$.credentialSubject.titular.nombres" },
                            filter = new { type = "string"}
                        },
                        // Incluimos el patrón general de tipo de VC para asegurar formato correcto
                        new {
                            path = new[] { "$.type[*]" },
                            filter = new { type = "string", pattern = "CertificadoEstudios" }
                        }
                    };

                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil empresa.");
                    break;

                // INSTITUTO → promedio AD/A en áreas de arte en todos los grados
                case "instituto":
                    fields = new object[] 
                    {
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].notas[*].area" },
                            filter = new { type = "string", pattern = "ARTE Y CULTURA" }
                        },
                        // Datos personales mínimos
                        new {
                            path = new[] { "$.credentialSubject.titular.numeroDocumento" },
                            filter = new { type = "string", minLength = 8 }
                        },
                        new {
                            path = new[] { "$.credentialSubject.titular.nombres" },
                            filter = new { type = "string", minLength = 2 }
                        },
                        // Incluimos el patrón general de tipo de VC para asegurar formato correcto
                        new {
                            path = new[] { "$.type[*]" },
                            filter = new { type = "string", pattern = "CertificadoEstudios" }
                        }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil instituto.");
                    break;

                // ENTIDAD PÚBLICA → cursa 5to grado en el presente año (2025)
                case "entidad-publica":
                    fields = new object[] 
                    {
                        new {
                            path = new[] { "$.credentialSubject.modalidad" },
                            filter = new { type = "string" }
                        },
                        new {
                            path = new[] { "$.credentialSubject.nivel" },
                            filter = new { type = "string" }
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos" },
                            filter = new { type = "array" }
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].grado" },
                            filter = new { type = "integer" }
                        },
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].anio" },
                            filter = new { type = "integer" }
                        },
                        // Situación final APROBADO
                        new {
                            path = new[] { "$.credentialSubject.gradosConcluidos[*].situacionFinal" },
                            filter = new { type = "string"}
                        },
                        // Incluimos el patrón general de tipo de VC para asegurar formato correcto
                        new {
                            path = new[] { "$.type[*]" },
                            filter = new { type = "string", pattern = "CertificadoEstudios" }
                        }
                    };
                    _logger.LogInformation("Arma solicitud de datos requeridos para validación de perfil entidad-publica.");
                    break;

                default:
                    fields = new object[] {
                        new {
                            path = new[] { "$.type[*]" },
                            filter = new { type = "string", pattern = "CertificadoEstudios" }
                        }
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

            var authRequest = new
            {
                client_id = callbackUrl,
                client_id_scheme = "redirect_uri",
                response_type = "vp_token",
                response_mode = "direct_post",
                response_uri = callbackUrl,
                state = s.State,
                nonce = s.Nonce,
                client_metadata = new
                {
                    client_name = clientName,
                    logo_uri    = $"{portalBase}/assets/empresa-logo.svg",
                    contacts    = new[] { clientContact }
                },
                presentation_definition = new
                {
                    id = "pd",
                    format = new { ldp_vc = new { proof_type = new[] { "JsonWebSignature2020" } } },
                    input_descriptors = new[] {
                        new {
                            id = "vc",
                            constraints = new { fields }
                        }
                    }
                }
            };

            var json = JsonSerializer.Serialize(
                authRequest,
                new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                });

            _logger.LogInformation("OIDC4VP Authorization Request:\n{Request}", json);

            return Ok(authRequest);
        }
    }
}
