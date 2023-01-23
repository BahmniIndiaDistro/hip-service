namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileEmailPhrPreVerificationRequest
    {
        public string transactionId;
        
        public string otp;

        public MobileEmailPhrPreVerificationRequest(string transactionId, string otp)
        {
            this.transactionId = transactionId;
            this.otp = otp;
        }
    }
}