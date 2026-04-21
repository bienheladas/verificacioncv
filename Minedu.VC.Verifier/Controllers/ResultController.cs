using Microsoft.AspNetCore.Mvc;
using Minedu.VC.Verifier.Services;

namespace Minedu.VC.Verifier.Controllers
{
    [Route("verifier/result")]
    [ApiController]
    public class ResultController : ControllerBase
    {
        private readonly SessionService _sessions;

        public ResultController(SessionService sessions)
        {
            _sessions = sessions;
        }

        [HttpGet("{sessionId}")]
        public IActionResult GetResult(string sessionId)
        {
            var s = _sessions.GetSession(sessionId);
            if (s is null) return NotFound();
            return Ok(new
            {
                session_id = s.SessionId,
                completed = s.Completed,
                result = s.Result
            });
        }
    }
}
