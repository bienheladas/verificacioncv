using Microsoft.AspNetCore.Mvc;
using Minedu.VC.Verifier.Services;
using System.Text.Json;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("verifier/callback")]
    [ApiController]
    public class CallbackController : ControllerBase
    {
        private readonly SessionService _sessions;
        private readonly VerificationService _verify;
        private readonly ILogger<CallbackController> _logger;

        public CallbackController(SessionService sessions, VerificationService verify, ILogger<CallbackController> logger)
        {
            _sessions = sessions;
            _verify = verify;
            _logger = logger;
        }

        // Inji envía la VP como application/x-www-form-urlencoded (spec OID4VP direct_post)
        [HttpPost("{sessionId}")]
        [Consumes("application/x-www-form-urlencoded", "application/json")]
        public async Task<IActionResult> ReceivePresentation(
            string sessionId,
            [FromForm] string? vp_token = null,
            [FromForm] string? presentation_submission = null,
            [FromForm] string? state = null)
        {
            _logger.LogInformation("Iniciando verificación de presentación para sesión {SessionId}", sessionId);

            var session = _sessions.GetSession(sessionId);
            if (session == null)
            {
                _logger.LogWarning("Sesión no encontrada: {SessionId}", sessionId);
                return NotFound("Sesion no encontrada.");
            }

            // Si llega como form-urlencoded, vp_token viene directo en el parámetro
            string? vpToken = vp_token;

            // Fallback: si llega como JSON (pruebas con Postman)
            if (string.IsNullOrEmpty(vpToken) && Request.ContentType?.Contains("application/json") == true)
            {
                using var reader = new StreamReader(Request.Body);
                var rawBody = await reader.ReadToEndAsync();
                if (!string.IsNullOrEmpty(rawBody))
                {
                    using var doc = JsonDocument.Parse(rawBody);
                    if (doc.RootElement.TryGetProperty("vp_token", out var el))
                        vpToken = el.ValueKind == JsonValueKind.String
                            ? el.GetString()
                            : el.GetRawText();
                }
            }

            if (string.IsNullOrEmpty(vpToken))
            {
                _logger.LogWarning("Solicitud sin vp_token en sesión {SessionId}", sessionId);
                return BadRequest(new { error = "Missing vp_token" });
            }

            _logger.LogInformation("vp_token recibido | SessionId={SessionId} | state={State}", sessionId, state);

            try
            {
                var baseResult = await _verify.VerifyPresentationAsync(vpToken);

                VerificationResult finalResult;
                if (!baseResult.Valid)
                {
                    _logger.LogWarning("Verificación base fallida | SessionId={SessionId} | Motivo={Reason}", sessionId, baseResult.Reason);
                    finalResult = baseResult;
                }
                else
                {
                    finalResult = await _verify.VerifyByProfileAsync(baseResult, session.Profile ?? "empresa", baseResult.VcNode);
                }

                _sessions.UpdateResult(sessionId, finalResult);
                _logger.LogInformation("Verificación completada | SessionId={SessionId} | Valid={Valid}", sessionId, finalResult.Valid);

                // OID4VP direct_post: el wallet solo acepta {} (el portal consulta el resultado por polling)
                return Ok(new { });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando verificación | SessionId={SessionId}", sessionId);
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }
}
