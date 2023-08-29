using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Verification.Model
{
    public class AuthorizedTokenRequest
    {
        public string healthId { get; }
        public string txnId { get; }
        
        [JsonConstructor]
        public AuthorizedTokenRequest(string healthId)
        {
            this.healthId = healthId;
        }
        
        public AuthorizedTokenRequest(string healthId, string txnId)
        {
            this.healthId = healthId;
            this.txnId = txnId;
        }
    }
}