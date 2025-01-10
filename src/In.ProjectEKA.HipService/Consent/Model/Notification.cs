namespace In.ProjectEKA.HipService.Consent.Model
{
    using Common.Model;

    public class Notification
    {
        public Notification(ConsentArtefact consentDetail, string consentId, string signature, ConsentStatus status, bool grantAcknowledgement)
        {
            ConsentDetail = consentDetail;
            ConsentId = consentId;
            Signature = signature;
            Status = status;
            GrantAcknowledgement = grantAcknowledgement;
        }

        public ConsentArtefact ConsentDetail { get; }

        public string ConsentId { get; }

        public string Signature { get; }

        public ConsentStatus Status { get; }
        
        public bool GrantAcknowledgement { get; }
    }
}