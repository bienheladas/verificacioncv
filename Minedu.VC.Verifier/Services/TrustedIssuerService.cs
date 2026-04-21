using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Services
{
    public class TrustedIssuerService
    {
        private readonly VerifierConfig _config;

        public TrustedIssuerService(IOptions<VerifierConfig> config)
        {
            _config = config.Value;
        }

        public bool IsTrusted(string issuer) =>
           _config.TrustedIssuers.Any(i =>
               issuer.StartsWith(i, StringComparison.OrdinalIgnoreCase));

        public IEnumerable<string> ListTrusted() => _config.TrustedIssuers;
    }
}
