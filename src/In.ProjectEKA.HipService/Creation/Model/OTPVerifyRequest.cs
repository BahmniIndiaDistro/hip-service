namespace In.ProjectEKA.HipService.Creation.Model
{
    public class OTPVerifyRequest
    {
        public string txnId { get; }
        public string otp { get;  }
        public OTPVerifyRequest(string txnId,string otp)
        {
            this.txnId = txnId;
            this.otp = otp;
        }
    }
}