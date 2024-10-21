using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileOTPGenerationResponse
    {
        public string txnId { get; }
        public string message { get;  }
        
        [JsonConstructor]
        public MobileOTPGenerationResponse(string txnId,string message)
        {
            this.txnId = txnId;
            this.message = message;
        }

        public MobileOTPGenerationResponse(string message)
        {
            this.message = message;
        }
    }
}