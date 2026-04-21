using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
            _logger.LogInformation("Empieza CreateSession");

            var session = _sessionService.CreateSession(profile);

            var callbackUrl = $"{_config.BaseApiUrl.TrimEnd('/')}{_config.CallbackPath}/{session.SessionId}";
            var requestUri = $"{_config.BaseApiUrl.TrimEnd('/')}/verifier/request/{session.SessionId}";

            _logger.LogInformation("callbackUrl={callbackUrl}", callbackUrl);
            _logger.LogInformation("requestUri={requestUri}", requestUri);

            string Encode(string v) => Uri.EscapeDataString(v);

            var clientMetadata = new
            {
                vp_formats = new
                {
                    ldp_vc = new
                    {
                        proof_type = new[] { "Ed25519Signature2020" }
                    }
                }
            };

            // QR con deepLink para obtener el 'Request Object' desde el 'Request Endpoint'
            //var qrUri = $"openid4vp://authorize?request_uri={Encode(requestUri)}";
            var qrUri =
                $"openid4vp://authorize?" +
                    $"client_id={_config.Did}" +
                    $"&client_id_scheme=did" +
                    $"&client_metadata={Encode(JsonSerializer.Serialize(clientMetadata))}" +
                    $"&request_uri ={Encode(requestUri)}";
            //    $"&response_mode=direct_post" +
            //    $"&response_type=vp_token";
            //    $"&response_uri={Encode(requestUri)}" +
            //    $"&nonce={session.Nonce}" +
            //    $"&state={session.State}";

            return Ok(new
            {
                session_id = session.SessionId,
                profile = profile,
                request_uri = requestUri,
                authorization_request = new { },
                qr_uri = qrUri
            });
        }
    }
}
