using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class NotifyAuth
    {
        public string transactionId { get; }
        public AuthNotifyStatus status { get;  }
        public string accessToken { get; }
        public Validity validity { get; }
        public AuthConfirmPatient patient { get; }

        public NotifyAuth(string transactionId, AuthNotifyStatus status, string accessToken, Validity validity, AuthConfirmPatient patient)
        {
            this.transactionId = transactionId;
            this.status = status;
            this.accessToken = accessToken;
            this.validity = validity;
            this.patient = patient;
        }
    }
}