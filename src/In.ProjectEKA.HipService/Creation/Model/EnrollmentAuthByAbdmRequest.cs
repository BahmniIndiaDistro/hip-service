using System;
using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.Creation.Model;

public class EnrollmentAuthByAbdmRequest
{
    public AuthDataModel AuthData { get; set; }
    public List<string> Scope { get; }
    public EnrollmentAuthByAbdmRequest(string txnId, List<ABHAScope> abhaEnrollmentScopes, string otpValue)
    {
        Scope = abhaEnrollmentScopes.Select(s => s.Value).ToList();
        AuthData = new AuthDataModel
        {
            AuthMethods = new List<string> { ABHAAuthMethods.OTP.Value },
            Otp = new OtpModel
            {
                TxnId = txnId,
                OtpValue = otpValue,
                Timestamp = DateTime.Now.ToString(Constants.TIMESTAMP_FORMAT)
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
        public string Timestamp { get; set; }
        public string OtpValue { get; set; }
    }
}