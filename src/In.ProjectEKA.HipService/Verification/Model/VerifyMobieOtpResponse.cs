using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    public class VerifyMobileOtpResponse
    {
        public string txnId;
        public string token;
        public List<MobileLinkedHid> mobileLinkedHid;

        public VerifyMobileOtpResponse(string txnId, string token, List<MobileLinkedHid> mobileLinkedHid)
        {
            this.txnId = txnId;
            this.token = token;
            this.mobileLinkedHid = mobileLinkedHid;
        }
    }
}