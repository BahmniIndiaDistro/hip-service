using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.Patient.Model
{
    public class ProfileShareConfirmation
    {
        public ProfileShareConfirmation(string requestId, string timestamp,
            ProfileShareAcknowledgement acknowledgement, Error error, Resp resp)
        {
            RequestId = requestId;
            Timestamp = timestamp;
            Acknowledgement = acknowledgement;
            Error = error;
            Resp = resp;
        }
        public string RequestId { get; }
        public string Timestamp { get; }
        public Error Error { get; }
        public Resp Resp { get; }
        public ProfileShareAcknowledgement Acknowledgement { get; }
    }
}