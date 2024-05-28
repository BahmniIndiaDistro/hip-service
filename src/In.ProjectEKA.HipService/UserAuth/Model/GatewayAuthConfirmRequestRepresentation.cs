using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class GatewayAuthConfirmRequestRepresentation
    {
        public Guid requestId { get; }
        public string timestamp { get; }
        public string transactionId { get; }
        public AuthConfirmCredential credential { get; }


        public GatewayAuthConfirmRequestRepresentation(Guid requestId, string timestamp, string transactionId,
            AuthConfirmCredential credential)
        {
            this.requestId = requestId;
            this.transactionId = transactionId;
            this.timestamp = timestamp;
            this.credential = credential;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}