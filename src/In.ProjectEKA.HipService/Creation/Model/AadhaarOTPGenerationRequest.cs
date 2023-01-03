namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarOTPGenerationRequest
    {
        public string aadhaar { get; }
        
        public AadhaarOTPGenerationRequest(string aadhaar)
        {
            this.aadhaar = aadhaar;
        }
    }
}