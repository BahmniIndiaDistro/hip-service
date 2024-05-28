namespace In.ProjectEKA.HipService.UserAuth.Model
{
    using System;
    using HipLibrary.Patient.Model;
    using Model;

    public class AuthOnNotifyResponse
    {
        public AuthOnNotifyResponse(Guid requestId, string timestamp,
            AuthOnNotifyAcknowledgement acknowledgement, Error error, Resp resp)
        {
            RequestId = requestId;
            Timestamp = timestamp;
            Acknowledgement = acknowledgement;
            Error = error;
            Resp = resp;
        }

        public Guid RequestId { get; }
        public string Timestamp { get; }
        public Error Error { get; }
        public Resp Resp { get; }
        public AuthOnNotifyAcknowledgement Acknowledgement { get; }
    }
}