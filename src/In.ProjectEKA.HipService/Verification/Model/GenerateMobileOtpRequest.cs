namespace In.ProjectEKA.HipService.Verification.Model
{
    public class GenerateMobileOtpRequest
    {
        public string mobile { get; }

        public GenerateMobileOtpRequest(string mobile)
        {
            this.mobile = mobile;
        }
    }
}