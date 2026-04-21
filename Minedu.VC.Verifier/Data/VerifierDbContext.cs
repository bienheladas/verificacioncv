using Microsoft.EntityFrameworkCore;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Data
{
    public class VerifierDbContext : DbContext
    {
        public VerifierDbContext(DbContextOptions<VerifierDbContext> options) : base(options) { }

        public DbSet<AsistenteEvento>   AsistentesEvento  => Set<AsistenteEvento>();
        public DbSet<RecojoDesayuno>    RecojosDesayuno   => Set<RecojoDesayuno>();
        public DbSet<EstudiantePadron>  EstudiantesPadron => Set<EstudiantePadron>();

        protected override void OnModelCreating(ModelBuilder mb)
        {
            mb.Entity<AsistenteEvento>(e =>
            {
                e.ToTable("cert_asistentes_evento");
                e.HasIndex(a => a.Dni).IsUnique();
            });

            mb.Entity<RecojoDesayuno>(e =>
            {
                e.ToTable("cert_recojo_desayuno");
                e.HasIndex(r => new { r.Dni, r.FechaRecojo });
            });

            mb.Entity<EstudiantePadron>(e =>
            {
                e.ToTable("cert_estudiante_for_vc");
                e.HasKey(p => p.Id);
            });
        }
    }
}
