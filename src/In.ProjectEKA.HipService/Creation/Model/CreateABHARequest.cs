

using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHARequest
    {
        public string healthId;

        public string txnId;

        public CreateABHARequest(string healthId, string txnId)
        {
            this.healthId = healthId;
            this.txnId = txnId;
        }
        
        [JsonConstructor]
        public CreateABHARequest(string healthId)
        {
            this.healthId = healthId;
        }
    }
}