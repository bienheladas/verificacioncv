namespace Minedu.VC.Verifier.Models
{
    public class Session
    {
        public string SessionId { get; set; } = Guid.NewGuid().ToString(); //Identificador único para correlacionar solicitud y respuesta
        public string State { get; set; } = Guid.NewGuid().ToString(); //Valor único generado para prevenir replay attacks
        public string Nonce { get; set; } = Guid.NewGuid().ToString(); //Valor usado en la presentación para ligarla a la solicitud
        public string Profile { get; set; } = "default"; //Perfil del verificador (útil si agregas varios roles)
        public string ResponseUri { get; set; } = default!; //Dónde la wallet debe enviar la VP (callback)
        public string? PresentationDefinitionUri { get; set; } //URL de la definición solicitada (según modo)
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; //Fecha/hora de creación
        public bool Completed { get; set; } = false; //Bandera que indica si la sesión ya tiene resultado
        public VerificationResult? Result { get; set; } //Resultado de la verificación (firma + contexto)
    }
}
