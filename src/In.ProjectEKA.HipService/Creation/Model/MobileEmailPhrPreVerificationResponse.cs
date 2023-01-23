using System.Collections.Generic;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileEmailPhrPreVerificationResponse
    {
        public string transactionId;

        public string mobileEmail;

        public List<string> mappedPhrAddress;

        [JsonConstructor]
        public MobileEmailPhrPreVerificationResponse(string transactionId, string mobileEmail, List<string> mappedPhrAddress)
        {
            this.transactionId = transactionId;
            this.mobileEmail = mobileEmail;
            this.mappedPhrAddress = mappedPhrAddress;
        }
        
        public MobileEmailPhrPreVerificationResponse(string mobileEmail, List<string> mappedPhrAddress)
        {
            this.mobileEmail = mobileEmail;
            this.mappedPhrAddress = mappedPhrAddress;
        }
        
    }
}