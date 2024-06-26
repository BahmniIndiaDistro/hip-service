namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using DataFlow.Model;
    using HipLibrary.Patient.Model;

    public class GatewayDataFlowRequestResponse
    {
        public GatewayDataFlowRequestResponse(
            Guid requestId,
            string timestamp,
            DataFlowRequestResponse hiRequest,
            Error error,
            Resp resp)
        {
            RequestId = requestId;
            Timestamp = timestamp;
            HiRequest = hiRequest;
            Error = error;
            Resp = resp;
        }

        public Guid RequestId { get; }
        public string Timestamp { get; }
        public DataFlowRequestResponse HiRequest { get; }
        public Error Error { get; }
        public Resp Resp { get; }
    }
}