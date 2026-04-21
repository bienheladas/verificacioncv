using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Minedu.VC.Verifier.Models
{
    [Table("cert_estudiante_for_vc")]
    public class EstudiantePadron
    {
        [Key]
        [Column("id_estudiante")]
        public int Id { get; set; }

        [Column("numero_documento")]
        public string NumeroDocumento { get; set; } = string.Empty;

        [Column("nombres")]
        public string Nombres { get; set; } = string.Empty;

        [Column("apellido_paterno")]
        public string ApellidoPaterno { get; set; } = string.Empty;

        [Column("apellido_materno")]
        public string ApellidoMaterno { get; set; } = string.Empty;
    }
}
