namespace In.ProjectEKA.HipService.Creation.Model;

public class AppVerifyAadhaarOTPRequest
{
    public string otp { get; }
    public string mobile { get; }
    
    public AppVerifyAadhaarOTPRequest(string otp, string mobile)
    {
        this.otp = otp;
        this.mobile = mobile;
    }
}