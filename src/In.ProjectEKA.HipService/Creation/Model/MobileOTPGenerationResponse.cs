using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileOTPGenerationResponse
    {
        public string txnId { get; }
        public string mobileLinked { get;  }
        
        [JsonConstructor]
        public MobileOTPGenerationResponse(string txnId,string mobileLinked)
        {
            this.txnId = txnId;
            this.mobileLinked = mobileLinked;
        }

        public MobileOTPGenerationResponse(string mobileLinked)
        {
            this.mobileLinked = mobileLinked;
        }
    }
}