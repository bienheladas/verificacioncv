using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Minedu.VC.Verifier.Models
{
    [Table("cert_recojo_desayuno")]
    public class RecojoDesayuno
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

        [Column("numero_camion")]
        [MaxLength(20)]
        public string NumeroCamion { get; set; } = string.Empty;

        // Fecha del recojo (solo fecha, para control de una vez por día)
        [Column("fecha_recojo")]
        public DateOnly FechaRecojo { get; set; }

        // Timestamp exacto del escaneo
        [Column("hora_recojo")]
        public DateTime HoraRecojo { get; set; }

        // Aprobado | Rechazado (fuera de horario, no en padrón, etc.)
        [Column("estado")]
        [MaxLength(20)]
        public string Estado { get; set; } = "Aprobado";

        [Column("motivo_rechazo")]
        [MaxLength(200)]
        public string? MotivoRechazo { get; set; }
    }
}
