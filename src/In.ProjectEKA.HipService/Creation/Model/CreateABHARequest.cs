

using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHARequest
    {
        public string txnId;

        public CreateABHARequest(string txnId)
        {
            this.txnId = txnId;
        }
        
    }
}