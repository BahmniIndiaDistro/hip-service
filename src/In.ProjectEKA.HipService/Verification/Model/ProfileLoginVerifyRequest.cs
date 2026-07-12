using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    /// <summary>
    /// Request for V3 API: Profile login verify OTP for particular ABHA ID.
    /// Body: scope, authData with authMethods and otp (txnId, otpValue).
    /// </summary>
    public class ProfileLoginVerifyRequest
    {
        public List<string> scope { get; set; }
        public ProfileAuthData authData { get; set; }
    }

    public class ProfileAuthData
    {
        public List<string> authMethods { get; set; }
        public ProfileOtpData otp { get; set; }
    }

    public class ProfileOtpData
    {
        public string txnId { get; set; }
        public string otpValue { get; set; }
    }
}
