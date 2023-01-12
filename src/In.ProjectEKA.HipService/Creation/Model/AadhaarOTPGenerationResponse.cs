using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarOTPGenerationResponse
    {
        public string txnId { get; }
        
        public string mobileNumber { get;  }
        
        [JsonConstructor]
        public AadhaarOTPGenerationResponse(string txnId,string mobileNumber)
        {
            this.txnId = txnId;
            this.mobileNumber = mobileNumber;
        }
        
        public AadhaarOTPGenerationResponse(string mobileNumber)
        {
            this.mobileNumber = mobileNumber;
        }
        
    }
}