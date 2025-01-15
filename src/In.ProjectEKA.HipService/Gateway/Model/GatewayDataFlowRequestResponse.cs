namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using DataFlow.Model;
    using HipLibrary.Patient.Model;

    public class GatewayDataFlowRequestResponse
    {
        public GatewayDataFlowRequestResponse(
            DataFlowRequestResponse hiRequest,
            Error error,
            Resp response)
        {
            HiRequest = hiRequest;
            Error = error;
            Response = response;
        }
        
        public DataFlowRequestResponse HiRequest { get; }
        public Error Error { get; }
        public Resp Response { get; }
    }
}