namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class AuthConfirmRequest
    {
        public string authCode { get; }
        public string healthId { get; }

        public AuthConfirmRequest(string authCode, string healthId)
        {
            this.authCode = authCode;
            this.healthId = healthId;
        }
    }
}