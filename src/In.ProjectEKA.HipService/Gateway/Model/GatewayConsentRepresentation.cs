namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using Common.Model;
    using HipLibrary.Patient.Model;

    public class GatewayConsentRepresentation
    {
        public GatewayConsentRepresentation(ConsentUpdateResponse acknowledgement, Error error, Resp response)
        {
            Acknowledgement = acknowledgement;
            Response = response;
            Error = error;
        }

        public ConsentUpdateResponse Acknowledgement { get; }
        public Resp Response { get; }
        public Error Error { get; }
    }
}