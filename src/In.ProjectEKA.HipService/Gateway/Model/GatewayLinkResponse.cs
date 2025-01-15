namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using HipLibrary.Patient.Model;

    public class GatewayLinkResponse
    {
        public GatewayLinkResponse(LinkEnquiryRepresentation link,
            Error error, Resp response, string transactionId)
        {
            Link = link;
            Error = error;
            Response = response;
            TransactionId = transactionId;
        }

        public LinkEnquiryRepresentation Link { get; }
        
        public string TransactionId { get; }

        public Error Error { get; }

        public Resp Response { get; }
    }
}