using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("openid-configuration")]
    [ApiController]
    public class WellKnownController : ControllerBase
    {
        private readonly VerifierConfig _config;

        public WellKnownController(IOptions<VerifierConfig> config)
        {
            _config = config.Value;
        }

        [HttpGet("openid-configuration")]
        public IActionResult GetMetadata()
        {
            var metadata = new
            {
                issuer = _config.BaseUrl,
                response_modes_supported = new[] { "direct_post" },
                grant_types_supported = new[] { "authorization_code" },
                vp_formats_supported = new[] { "ldp_vc" },
                presentation_definition_uri_supported = true,
                presentation_submission_supported = true
            };
            return Ok(metadata);
        }
    }
}
