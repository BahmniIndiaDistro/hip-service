using In.ProjectEKA.HipService.Link.Model;

namespace In.ProjectEKA.HipService.Patient.Model
{
    using System;
    using HipLibrary.Patient.Model;
    using Model;

    public class HipPatientNotifyConfirmation
    {
        public HipPatientNotifyConfirmation(string requestId, string timestamp,
            PatientNotifyAcknowledgement acknowledgement, Error error, Resp resp)
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
        public PatientNotifyAcknowledgement Acknowledgement { get; }
    }
}