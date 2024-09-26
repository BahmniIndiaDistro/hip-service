using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarOTPGenerationResponse
    {
        public string txnId { get; }
        
        public string message { get;  }
        
        [JsonConstructor]
        public AadhaarOTPGenerationResponse(string txnId,string message)
        {
            this.txnId = txnId;
            this.message = message;
        }
        
        public AadhaarOTPGenerationResponse(string message)
        {
            this.message = message;
        }
        
    }
}