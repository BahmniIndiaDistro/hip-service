using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using HipLibrary.Patient.Model;

    public class GatewayLinkConfirmResponse
    {
        public GatewayLinkConfirmResponse(
            IEnumerable<LinkConfirmationRepresentation> patient,
            Error error,
            Resp response)
        {
            Patient = patient;
            Error = error;
            Response = response;
        }
        public IEnumerable<LinkConfirmationRepresentation> Patient { get; }

        public Error Error { get; }

        public Resp Response { get; }
    }
}