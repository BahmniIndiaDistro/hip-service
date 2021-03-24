using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class OnAuthConfirmRequest
    {
        public Guid requestID { get; }
        public DateTime timestamp { get; }
        public OnConfirmAuth auth { get; }
        public Error error { get; }
        public Resp resp { get; }


        public OnAuthConfirmRequest(Guid requestId, DateTime timestamp, OnConfirmAuth auth, Error error, Resp resp)
        {
            this.requestID = requestId;
            this.timestamp = timestamp;
            this.auth = auth;
            this.error = error;
            this.resp = resp;
        }
    }
}