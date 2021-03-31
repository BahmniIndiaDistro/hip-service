namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class AuthConfirmCredential
    {
        public string authCode { get; set; }

        public AuthConfirmCredential(string authCode)
        {
            this.authCode = authCode;
        }
    }
}