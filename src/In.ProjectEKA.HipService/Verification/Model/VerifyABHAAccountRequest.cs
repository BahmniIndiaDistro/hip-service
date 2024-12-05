using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Verification.Model
{
    public class VerifyABHAAccountRequest
    {
        [JsonProperty("ABHANumber")]
        public string ABHANumber { get; }
        public string txnId { get; }
        
        [JsonConstructor]
        public VerifyABHAAccountRequest(string abhaNumber)
        {
            this.ABHANumber = abhaNumber;
        }
        
        public VerifyABHAAccountRequest(string abhaNumber, string txnId)
        {
            this.ABHANumber = abhaNumber;
            this.txnId = txnId;
        }
    }
}