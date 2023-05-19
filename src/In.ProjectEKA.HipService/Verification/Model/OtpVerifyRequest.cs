namespace In.ProjectEKA.HipService.Verification.Model
{
    public class OtpVerifyRequest
    {
        public string otp { get; }
        public AuthMode authMethod { get; }
        
        public OtpVerifyRequest(string otp, AuthMode authMethod)
        {
            this.otp = otp;
            this.authMethod = authMethod;
        }
    }
}