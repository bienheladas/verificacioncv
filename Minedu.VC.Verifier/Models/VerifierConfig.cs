namespace Minedu.VC.Verifier.Models
{
    public class VerifierConfig
    {
        public string BaseUrl { get; set; } = string.Empty;
        public string BaseApiUrl { get; set; } = string.Empty;
        public string PortalBaseUrl { get; set; } = string.Empty;
        public string CallbackPath { get; set; } = "/verifier/callback";
        public string SchemaBaseUrl { get; set; } = string.Empty;
        public string Did { get; set; } = string.Empty;
        public List<string> TrustedIssuers { get; set; } = new();
    }
}
