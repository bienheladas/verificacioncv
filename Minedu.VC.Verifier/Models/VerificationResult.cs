using System.Text.Json.Nodes;

namespace Minedu.VC.Verifier.Models
{
    public class VerificationResult
    {
        public bool Valid { get; set; }
        public string Reason { get; set; } = string.Empty;
        public string? Issuer { get; set; }
        public string? Subject { get; set; }
        public string? Context { get; set; }
        public string? Profile { get; set; }
        public JsonNode? VcNode { get; set; }  // Agregado
        public string? Status { get; set; }    // Opcional, para el resultado de la lista de estados
        public DateTime CheckedAt { get; set; } = DateTime.UtcNow;

        // Datos adicionales del VC parseado
        public Dictionary<string, object>? Data { get; set; }

        // Lista detallada de verificaciones
        public List<VerificationCheck> Checks { get; set; } = new();

        // Resumen general mostrado en el frontend
        public Dictionary<string, object>? Summary { get; set; }

        public VerificationResult Clone()
        {
            return (VerificationResult)this.MemberwiseClone();
        }
    }

    public class VerificationCheck
    {
        public string Name { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
