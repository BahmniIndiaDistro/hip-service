namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAAddressRequest
    {
        public string abhaAddress;
        public string txnId;
        public int preferred = 1;

        public CreateABHAAddressRequest(string txnId, string abhaAddress)
        {
            this.txnId = txnId;
            this.abhaAddress = abhaAddress;
        }
    }
}