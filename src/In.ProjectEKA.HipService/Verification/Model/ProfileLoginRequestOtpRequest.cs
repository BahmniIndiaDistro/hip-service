using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    /// <summary>
    /// Request for V3 API: Request OTP for the specific index from ABHA search list.
    /// txnId is from the response of search-by-mobile API.
    /// </summary>
    public class ProfileLoginRequestOtpRequest
    {
        public List<string> scope { get; set; }
        public string loginHint { get; set; }
        public string loginId { get; set; }
        public string otpSystem { get; set; }
        public string txnId { get; set; }
    }
}
