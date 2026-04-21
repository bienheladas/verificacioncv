using Microsoft.EntityFrameworkCore;
using Minedu.VC.Verifier.Data;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Services
{
    public class AttendeeService
    {
        private readonly IDbContextFactory<VerifierDbContext> _dbFactory;
        private readonly ILogger<AttendeeService> _logger;

        public AttendeeService(IDbContextFactory<VerifierDbContext> dbFactory, ILogger<AttendeeService> logger)
        {
            _dbFactory = dbFactory;
            _logger = logger;
        }

        /// <summary>
        /// Verifica si el DNI está en la tabla de invitados y registra/actualiza la asistencia.
        /// La fuente de verdad es la DB — no hay lista hardcodeada.
        /// </summary>
        public async Task<(bool EsInvitado, bool YaRegistrado, AsistenteEvento? Registro)> VerificarYRegistrarAsync(
            string dni, string nombres, string apellidos)
        {
            var key = dni.Trim();
            await using var db = await _dbFactory.CreateDbContextAsync();

            var existente = await db.AsistentesEvento.FirstOrDefaultAsync(a => a.Dni == key);
            if (existente == null)
            {
                _logger.LogWarning("DNI no encontrado en lista de invitados | DNI={Dni}", key);
                return (false, false, null);
            }

            var ahora = DateTime.UtcNow;
            bool yaRegistrado = existente.Estado == "Registrado" || existente.Estado == "YaRegistrado";

            existente.Estado         = yaRegistrado ? "YaRegistrado" : "Registrado";
            existente.UltimoAccesoEn = ahora;
            existente.IntentosAcceso += 1;
            if (existente.PrimerAccesoEn == null)
                existente.PrimerAccesoEn = ahora;

            await db.SaveChangesAsync();
            _logger.LogInformation("Asistencia procesada | DNI={Dni} | Estado={Estado} | Intentos={Intentos}",
                key, existente.Estado, existente.IntentosAcceso);
            return (true, yaRegistrado, existente);
        }

        public async Task<List<AsistenteEvento>> ObtenerAsistentesAsync()
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            return await db.AsistentesEvento.OrderBy(a => a.PrimerAccesoEn).ToListAsync();
        }
    }
}
