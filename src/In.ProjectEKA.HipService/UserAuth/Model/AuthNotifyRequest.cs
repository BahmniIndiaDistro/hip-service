using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class AuthNotifyRequest
    {
        public Guid requestId { get; }
        public DateTime timestamp { get; }
        public NotifyAuth auth { get; }

        public AuthNotifyRequest(Guid requestId, DateTime timestamp, NotifyAuth auth)
        {
            this.requestId = requestId;
            this.timestamp = timestamp;
            this.auth = auth;
        }
    }
}