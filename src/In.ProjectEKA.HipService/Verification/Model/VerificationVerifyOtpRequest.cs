namespace In.ProjectEKA.HipService.Verification.Model;

public class VerificationVerifyOtpRequest
{
    public string otp { get; }
    public VerificationVerifyOtpRequest(string otp)
    {
        this.otp = otp;
    }
}