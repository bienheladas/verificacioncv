using Microsoft.EntityFrameworkCore;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Data
{
    public class VerifierDbContext : DbContext
    {
        public VerifierDbContext(DbContextOptions<VerifierDbContext> options) : base(options) { }

        public DbSet<AsistenteEvento> AsistentesEvento => Set<AsistenteEvento>();

        protected override void OnModelCreating(ModelBuilder mb)
        {
            mb.Entity<AsistenteEvento>(e =>
            {
                e.ToTable("cert_asistentes_evento");
                e.HasIndex(a => a.Dni).IsUnique();
            });
        }
    }
}
