using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using HipLibrary.Patient.Model;

    public class GatewayDiscoveryRepresentation
    {
        public GatewayDiscoveryRepresentation(IEnumerable<PatientDiscoveryRepresentation> patient,
            IEnumerable<string> matchedBy,
            string transactionId,
            Error error,
            DiscoveryResponse response)
        {
            Patient = patient;
            MatchedBy = matchedBy;
            TransactionId = transactionId;
            Error = error;
            Response = response;
        }

        public IEnumerable<PatientDiscoveryRepresentation> Patient { get; }
        public IEnumerable<string> MatchedBy { get; }
        public string TransactionId { get; }
        public Error Error { get; }
        public Resp Response { get; }
    }
}