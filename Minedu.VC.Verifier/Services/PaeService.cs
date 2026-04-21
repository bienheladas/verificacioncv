using Microsoft.EntityFrameworkCore;
using Minedu.VC.Verifier.Data;
using Minedu.VC.Verifier.Models;

namespace Minedu.VC.Verifier.Services
{
    public record PaeVerificacion(
        bool EnPadron,
        bool EnHorario,
        bool YaRecogio,
        RecojoDesayuno? Registro
    );

    public class PaeService
    {
        private static readonly TimeZoneInfo _limaTz =
            TimeZoneInfo.FindSystemTimeZoneById("America/Lima");

        private const string NumeroCamion = "C-042"; // ficticio para el prototipo

        private readonly IDbContextFactory<VerifierDbContext> _dbFactory;
        private readonly ILogger<PaeService> _logger;

        public PaeService(IDbContextFactory<VerifierDbContext> dbFactory, ILogger<PaeService> logger)
        {
            _dbFactory = dbFactory;
            _logger = logger;
        }

        public static bool EsHorarioValido(out DateTime horaLima)
        {
            horaLima = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _limaTz);
            return horaLima.Hour >= 6 && horaLima.Hour < 12;
        }

        public async Task<PaeVerificacion> VerificarYRegistrarAsync(
            string dni, string nombres, string apellidos, bool registrar)
        {
            var key = dni.Trim();
            await using var db = await _dbFactory.CreateDbContextAsync();

            // 1. Padrón
            var enPadron = await db.EstudiantesPadron
                .AnyAsync(e => e.NumeroDocumento == key);

            bool enHorario = EsHorarioValido(out var horaLima);
            var hoy = DateOnly.FromDateTime(horaLima);

            if (!enPadron)
            {
                _logger.LogWarning("DNI no en padrón PAE | DNI={Dni}", key);
                return new PaeVerificacion(false, enHorario, false, null);
            }

            // 2. ¿Ya recogió hoy?
            var yaRecogio = await db.RecojosDesayuno
                .AnyAsync(r => r.Dni == key && r.FechaRecojo == hoy && r.Estado == "Aprobado");

            if (!registrar)
                return new PaeVerificacion(true, enHorario, yaRecogio, null);

            // 3. Registrar intento (aprobado o rechazado)
            string estado = (enHorario && !yaRecogio) ? "Aprobado" : "Rechazado";
            string? motivo = !enHorario ? "Fuera del horario permitido (6am–12pm)"
                           : yaRecogio  ? "Desayuno ya retirado hoy"
                           : null;

            var registro = new RecojoDesayuno
            {
                Dni           = key,
                Nombres       = nombres,
                Apellidos     = apellidos,
                NumeroCamion  = NumeroCamion,
                FechaRecojo   = hoy,
                HoraRecojo    = DateTime.UtcNow,
                Estado        = estado,
                MotivoRechazo = motivo
            };
            db.RecojosDesayuno.Add(registro);
            await db.SaveChangesAsync();

            _logger.LogInformation("Recojo registrado | DNI={Dni} | Estado={Estado} | Camion={Camion}",
                key, estado, NumeroCamion);

            return new PaeVerificacion(true, enHorario, yaRecogio, registro);
        }
    }
}
