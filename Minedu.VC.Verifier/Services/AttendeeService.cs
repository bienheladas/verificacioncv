using Microsoft.EntityFrameworkCore;
using Minedu.VC.Verifier.Data;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Services
{
    public class AttendeeService
    {
        private static readonly HashSet<string> _invitados = new(StringComparer.OrdinalIgnoreCase)
        {
            "72559262", "72145969", "78959604", "70389552", "73174695",
            "74534933", "79508236", "73913066", "74015173"
        };

        private readonly IDbContextFactory<VerifierDbContext> _dbFactory;
        private readonly ILogger<AttendeeService> _logger;

        public AttendeeService(IDbContextFactory<VerifierDbContext> dbFactory, ILogger<AttendeeService> logger)
        {
            _dbFactory = dbFactory;
            _logger = logger;
        }

        public bool EsInvitado(string dni) => _invitados.Contains(dni.Trim());

        public async Task<(bool YaRegistrado, AsistenteEvento Registro)> RegistrarAsistenciaAsync(
            string dni, string nombres, string apellidos)
        {
            var key = dni.Trim();
            await using var db = await _dbFactory.CreateDbContextAsync();

            var existente = await db.AsistentesEvento.FirstOrDefaultAsync(a => a.Dni == key);
            var ahora = DateTime.UtcNow;

            if (existente != null)
            {
                existente.Estado          = "YaRegistrado";
                existente.UltimoAccesoEn  = ahora;
                existente.IntentosAcceso += 1;
                await db.SaveChangesAsync();
                _logger.LogInformation("Asistencia duplicada | DNI={Dni} | Intentos={Intentos}", key, existente.IntentosAcceso);
                return (true, existente);
            }

            var nuevo = new AsistenteEvento
            {
                Dni             = key,
                Nombres         = nombres,
                Apellidos       = apellidos,
                Estado          = "Registrado",
                PrimerAccesoEn  = ahora,
                UltimoAccesoEn  = ahora,
                IntentosAcceso  = 1
            };
            db.AsistentesEvento.Add(nuevo);
            await db.SaveChangesAsync();
            _logger.LogInformation("Asistencia registrada | DNI={Dni} | Nombres={Nombres}", key, nombres);
            return (false, nuevo);
        }

        public async Task<List<AsistenteEvento>> ObtenerAsistentesAsync()
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            return await db.AsistentesEvento.OrderBy(a => a.PrimerAccesoEn).ToListAsync();
        }
    }
}
