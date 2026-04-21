namespace Minedu.VC.Verifier.Services
{
    public record AttendeeRecord(string Nombres, string Apellidos, string Dni, DateTime RegistradoEn);

    public class AttendeeService
    {
        private static readonly HashSet<string> _invitados = new(StringComparer.OrdinalIgnoreCase)
        {
            "72559262", "72145969", "78959604", "70389552", "73174695",
            "74534933", "79508236", "73913066", "74015173"
        };

        private readonly Dictionary<string, AttendeeRecord> _asistentes = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new();

        public bool EsInvitado(string dni) => _invitados.Contains(dni.Trim());

        public (bool YaRegistrado, AttendeeRecord? Registro) RegistrarAsistencia(string dni, string nombres, string apellidos)
        {
            var key = dni.Trim();
            lock (_lock)
            {
                if (_asistentes.TryGetValue(key, out var existing))
                    return (true, existing);

                var registro = new AttendeeRecord(nombres, apellidos, key, DateTime.Now);
                _asistentes[key] = registro;
                return (false, registro);
            }
        }

        public IReadOnlyList<AttendeeRecord> ObtenerAsistentes()
        {
            lock (_lock)
                return _asistentes.Values.OrderBy(r => r.RegistradoEn).ToList();
        }
    }
}
