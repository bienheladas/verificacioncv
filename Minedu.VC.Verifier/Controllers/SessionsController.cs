using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;
using Minedu.VC.Verifier.Services;
using System.Text.Json;
using System.Text.Json.Serialization;

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

            var requestUri = $"{_config.BaseApiUrl.TrimEnd('/')}/verifier/request/{session.SessionId}";

            // QR corto: wallet descarga el request completo desde request_uri (~240 chars total)
            var qrUri =
                $"openid4vp://authorize?" +
                $"client_id={Encode(callbackUrl)}" +
                $"&client_id_scheme=redirect_uri" +
                $"&request_uri={Encode(requestUri)}";

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

        private static object BuildPresentationDefinition(string profile, string schemaUrl)
        {
            // PD mínimo: solo exige que la VC sea de tipo CertificadoEstudios.
            // La validación por perfil (grados, notas, situación) se hace server-side en VerificationService.
            object[] fields = new object[]
            {
                new { path = new[] { "$.type[*]" }, filter = new { type = "string", pattern = "CertificadoEstudios" } }
            };

            return new
            {
                id = "pd",
                format = new { ldp_vc = new { proof_type = new[] { "JsonWebSignature2020" } } },
                input_descriptors = new[]
                {
                    new { id = "vc", constraints = new { fields } }
                }
            };
        }
    }
}
