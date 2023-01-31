using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileEmailPhrPreVerificationRequest
    {
        public string transactionId;
        
        public string otp;
        public bool isHealthIdNumberOtp { get; }

        public MobileEmailPhrPreVerificationRequest(string transactionId, string otp)
        {
            this.transactionId = transactionId;
            this.otp = otp;
        }
        
        [JsonConstructor]
        public MobileEmailPhrPreVerificationRequest(string otp, bool isHealthIdNumberOtp = false)
        {
            this.otp = otp;
            this.isHealthIdNumberOtp = isHealthIdNumberOtp;
        }
    }
}