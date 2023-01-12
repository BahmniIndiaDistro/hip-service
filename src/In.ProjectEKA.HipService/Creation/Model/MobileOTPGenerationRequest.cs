using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileOTPGenerationRequest
    {
        public string txnId { get; }
        public string mobile { get;  }
        
        public MobileOTPGenerationRequest(string txnId,string mobile)
        {
            this.txnId = txnId;
            this.mobile = mobile;
        }
        
        [JsonConstructor]
        public MobileOTPGenerationRequest(string mobile)
        {
            this.mobile = mobile;
        }
    }
}