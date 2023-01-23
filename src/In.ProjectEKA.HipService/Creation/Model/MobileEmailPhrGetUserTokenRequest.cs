using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileEmailPhrGetUserTokenRequest
    {
        public string phrAddress;

        public string transactionId;
        
        [JsonConstructor]
        public MobileEmailPhrGetUserTokenRequest(string phrAddress)
        {
            this.phrAddress = phrAddress;
        }
        
        public MobileEmailPhrGetUserTokenRequest(string phrAddress, string transactionId)
        {
            this.phrAddress = phrAddress;
            this.transactionId = transactionId;
        }
    }
}