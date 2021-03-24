namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class OnConfirmAuth
    {
        public string accessToken { get; }
        public Validity validity { get; }
        public AuthConfirmPatient patient { get; }

        public OnConfirmAuth(string accessToken, Validity validity, AuthConfirmPatient patient)
        {
            this.accessToken = accessToken;
            this.validity = validity;
            this.patient = patient;
        }
    }
}