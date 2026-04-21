using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Minedu.VC.Verifier.Models
{
    [Table("cert_asistentes_evento")]
    public class AsistenteEvento
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Column("dni")]
        [MaxLength(15)]
        public string Dni { get; set; } = string.Empty;

        [Column("nombres")]
        [MaxLength(200)]
        public string Nombres { get; set; } = string.Empty;

        [Column("apellidos")]
        [MaxLength(200)]
        public string Apellidos { get; set; } = string.Empty;

        // Estado: Pendiente | Registrado | YaRegistrado
        [Column("estado")]
        [MaxLength(30)]
        public string Estado { get; set; } = "Pendiente";

        [Column("primer_acceso_en")]
        public DateTime? PrimerAccesoEn { get; set; }

        [Column("ultimo_acceso_en")]
        public DateTime? UltimoAccesoEn { get; set; }

        [Column("intentos_acceso")]
        public int IntentosAcceso { get; set; } = 0;
    }
}
