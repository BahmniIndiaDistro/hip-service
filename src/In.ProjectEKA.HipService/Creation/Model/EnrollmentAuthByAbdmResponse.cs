namespace In.ProjectEKA.HipService.Creation.Model
{
    public class EnrollmentAuthByAbdmResponse
    {
        public string txnId { get; }
        public string authResult { get; }
        public string message { get; }

        public EnrollmentAuthByAbdmResponse(string txnId, string authResult, string message)
        {
            this.txnId = txnId;
            this.authResult = authResult;
            this.message = message;
        }
    }
}