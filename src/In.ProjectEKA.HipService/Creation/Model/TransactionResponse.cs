namespace In.ProjectEKA.HipService.Creation.Model
{
    public class TransactionResponse
    {
        public string txnId { get; }
     
            public TransactionResponse(string txnId)
            {
                this.txnId = txnId;
            }
    }
}