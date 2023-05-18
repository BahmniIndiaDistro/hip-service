namespace In.ProjectEKA.HipService.Verification.Model
{
    public class AuthInitResponse
    {
        public string txnId;

        public AuthInitResponse(string txnId)
        {
            this.txnId = txnId;
        }
    }
}