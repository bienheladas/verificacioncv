using Microsoft.AspNetCore.Mvc;
using Minedu.VC.Verifier.Services;
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;

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

        [HttpPost("{sessionId}")]
        public async Task<IActionResult> ReceivePresentation(string sessionId, [FromBody] JsonElement body)
        {
            _logger.LogInformation("Iniciando verificación de presentación para sesión {SessionId}", sessionId);

            // 0) Validar sesion 
            var session = _sessions.GetSession(sessionId);
            if (session == null) 
            {
                _logger.LogWarning("Sesión no encontrada: {SessionId}", sessionId);
                return NotFound("Sesion no encontrada."); 
            }

            // 1) Validar que venga vp_token
            if (!body.TryGetProperty("vp_token", out var vpTokenElement))
            {
                _logger.LogWarning("Solicitud sin vp_token en sesión {SessionId}", sessionId);
                return BadRequest(new { error = "Missing vp_token" });
            }
                

            string? vpToken = null;

            if (vpTokenElement.ValueKind == JsonValueKind.String)
            {
                // Caso común: viene como string (JWS o JSON serializado)
                _logger.LogInformation("vpTokenElement viene como string (JWS o JSON serializado). ValueKind: {vpTokenElement.ValueKind}", vpTokenElement.ValueKind);
                vpToken = vpTokenElement.GetString();
            }
            else if (vpTokenElement.ValueKind == JsonValueKind.Object)
            {
                // Caso: viene como objeto JSON
                _logger.LogInformation("vpTokenElement viene como objeto JSON. ValueKind: {vpTokenElement.ValueKind}", vpTokenElement.ValueKind);
                vpToken = vpTokenElement.GetRawText();
            }
            else
            {
                _logger.LogWarning("Formato vp_token inválido en sesión {SessionId}", sessionId);
                return BadRequest(new { error = "Formato vp_token inválido." });
            }

            try 
            {
                _logger.LogInformation("Enviando vp_token a VerificationService.VerifyPresentationAsync");

                // 2.1) Llamar al servicio de verificacion de presentacion (1 parámetro)
                var baseResult = await _verify.VerifyPresentationAsync(vpToken ?? string.Empty);

                if (!baseResult.Valid)
                {
                    _logger.LogWarning("Verificación base fallida | SessionId={SessionId} | Motivo={Reason}", sessionId, baseResult.Reason);
                    return Ok(baseResult);
                }

                _logger.LogInformation("Ejecutando verificación contextual | SessionId={SessionId} | Perfil={Profile}", sessionId, session.Profile ?? "empresa");

                // 2.2) Llamar al servicio de verificacion de reglas de negocio
                var extendedResult = await _verify.VerifyByProfileAsync(baseResult, session.Profile ?? "empresa", baseResult.VcNode);

                // 3) Guardar resultado en la sesión
                _sessions.UpdateResult(sessionId, extendedResult);

                _logger.LogInformation("Verificación completada | SessionId={SessionId} | Valid={Valid} | Issuer={Issuer} | Subject={Subject}",
                    sessionId, extendedResult.Valid, extendedResult.Issuer, extendedResult.Subject);

                // 4) Responder
                return Ok(extendedResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error procesando verificación | SessionId={SessionId}", sessionId);
                return StatusCode(500, new { error = ex.Message });
            }
            
        }
    }
}
