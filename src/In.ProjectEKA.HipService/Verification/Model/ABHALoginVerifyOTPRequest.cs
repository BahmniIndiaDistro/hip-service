using System;
using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.Verification.Model;

public class ABHALoginVerifyOTPRequest
{
    public AuthDataModel AuthData { get; set; }
    public List<string> Scope { get; }
    public ABHALoginVerifyOTPRequest(string txnId, List<string> abhaScopes, string otpValue)
    {
        Scope = abhaScopes;
        AuthData = new AuthDataModel
        {
            AuthMethods = new List<string> { ABHAAuthMethods.OTP.Value },
            Otp = new OtpModel
            {
                TxnId = txnId,
                OtpValue = otpValue
            }
        };
    }
    public class AuthDataModel
    {
        public List<string> AuthMethods { get; set; }
        public OtpModel Otp { get; set; }
    }

    public class OtpModel
    {
        public string TxnId { get; set; }
        public string OtpValue { get; set; }
    }
    
}
