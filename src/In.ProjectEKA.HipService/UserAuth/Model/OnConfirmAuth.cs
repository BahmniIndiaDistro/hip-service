using System;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class OnConfirmAuth
    {
        public string accessToken { get; }
        public Validity validity { get; }
        public DateTime expiry { get; }
        public string limit { get; }
        public AuthConfirmPatient patient { get; }

        public OnConfirmAuth(string accessToken, Validity validity, DateTime expiry, string limit, AuthConfirmPatient patient)
        {
            this.accessToken = accessToken;
            this.validity = validity;
            this.expiry = expiry;
            this.limit = limit;
            this.patient = patient;
        }
    }
}