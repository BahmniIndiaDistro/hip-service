using System;
using System.Collections.Generic;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAEnrollByAadhaarRequest
{
    public AuthDataModel AuthData { get; set; }
    public ConsentModel Consent { get; set; }
    
    public ABHAEnrollByAadhaarRequest(string txnId,string otpValue, string mobileNumber)
    {
        AuthData = new AuthDataModel
        {
            AuthMethods = new List<string> { ABHAAuthMethods.OTP.Value },
            Otp = new OtpModel
            {
                TxnId = txnId,
                OtpValue = otpValue,
                Mobile = mobileNumber,
                Timestamp = DateTime.Now.ToString(Constants.TIMESTAMP_FORMAT)
            }
        };
        Consent = new ConsentModel
        {
            Code = "abha-enrollment",
            Version = "1.4"
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
        public  string Timestamp { get; set; }
        public string OtpValue { get; set; }
        public string Mobile { get; set; }
    }

    public class ConsentModel
    {
        public string Code { get; set; }
        public string Version { get; set; }
    }
}


