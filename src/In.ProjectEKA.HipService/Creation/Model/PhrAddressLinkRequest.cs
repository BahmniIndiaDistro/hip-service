using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class PhrAddressLinkRequest
    {
        public string action;

        public string transactionId;
        
        [JsonConstructor]
        public PhrAddressLinkRequest(string action)
        {
            this.action = action;
        }

        public PhrAddressLinkRequest(string action, string transactionId)
        {
            this.action = action;
            this.transactionId = transactionId;
        }
    }
}