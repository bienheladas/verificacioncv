using Microsoft.Extensions.Options;
using Minedu.VC.Verifier.Models;
using System.Collections.Concurrent;
using System.Runtime;

namespace Minedu.VC.Verifier.Services
{
    public class SessionService
    {
        private readonly VerifierConfig _config;
        private readonly ConcurrentDictionary<string, Session> _sessions = new();

        public SessionService(IOptions<VerifierConfig> config)
        {
            _config = config.Value;
        }

        public Session CreateSession(string profile)
        {
            var s = new Session
            {
                SessionId = Guid.NewGuid().ToString("N"),
                State = Guid.NewGuid().ToString("N"),
                Nonce = Guid.NewGuid().ToString("N"),
                Profile = profile.ToLower(),
                ResponseUri = $"{_config.BaseApiUrl.TrimEnd('/')}{_config.CallbackPath}/"
            };
            _sessions[s.SessionId] = s;
            return s;
        }

        public Session? GetSession(string id) =>
            _sessions.TryGetValue(id, out var s) ? s : null;

        public void UpdateResult(string id, VerificationResult result)
        {
            if (_sessions.TryGetValue(id, out var s))
            {
                s.Result = result;
                s.Completed = true;
            }
        }
    }
}
