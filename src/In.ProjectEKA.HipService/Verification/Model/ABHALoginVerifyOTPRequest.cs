using System;
using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.Verification.Model;

public class ABHALoginVerifyOTPRequest
{
    public AuthDataModel authData { get; set; }
    public List<string> scope { get; }
    public ABHALoginVerifyOTPRequest(string txnId, List<string> abhaScopes, string otpValue)
    {
        scope = abhaScopes;
        authData = new AuthDataModel
        {
            authMethods = new List<string> { ABHAAuthMethods.OTP.Value },
            otp = new OtpModel
            {
                txnId = txnId,
                otpValue = otpValue
            }
        };
    }
    public class AuthDataModel
    {
        public List<string> authMethods { get; set; }
        public OtpModel otp { get; set; }
    }

    public class OtpModel
    {
        public string txnId { get; set; }
        public string otpValue { get; set; }
    }
    
}
