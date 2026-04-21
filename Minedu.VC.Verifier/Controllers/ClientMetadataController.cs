using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("verifier/client-metadata")]
    [ApiController]
    public class ClientMetadataController : ControllerBase
    {
        private readonly VerifierConfig _config;

        public ClientMetadataController(IOptions<VerifierConfig> cfg)
        {
            _config = cfg.Value;
        }

        [HttpGet("{profile}")]
        public IActionResult Get(string profile)
        {
            var portalBase = _config.PortalBaseUrl.TrimEnd('/');
            var (clientName, clientContact) = profile.ToLower() switch
            {
                "empresa"         => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos"),
                "instituto"       => ("Instituto Nacional de Arte del Perú", "Oficina de Admisión"),
                "entidad-publica" => ("Min. de Trabajo y Promoción del Empleo", "Dir. de Capacitación"),
                _                 => ("TechPerú Empleos S.A.C.", "Área de Recursos Humanos")
            };

            return Ok(new
            {
                client_name = clientName,
                logo_uri    = $"{portalBase}/assets/empresa-logo.svg",
                contacts    = new[] { clientContact }
            });
        }
    }
}
