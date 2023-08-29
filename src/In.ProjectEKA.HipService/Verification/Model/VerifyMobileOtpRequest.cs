namespace In.ProjectEKA.HipService.Verification.Model
{
    public class VerifyMobileOtpRequest
    {
        public string otp { get; }

        public VerifyMobileOtpRequest(string otp)
        {
            this.otp = otp;
        }
    }
}