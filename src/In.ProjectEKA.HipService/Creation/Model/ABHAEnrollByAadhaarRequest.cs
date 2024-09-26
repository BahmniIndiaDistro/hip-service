using System;
using System.Collections.Generic;
using In.ProjectEKA.HipService.Common;

namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAEnrollByAadhaarRequest
{
    public AuthData AuthData { get; set; }
    public Consent Consent { get; set; }
    
    public ABHAEnrollByAadhaarRequest(string txnId,string otpValue, string mobileNumber)
    {
        AuthData = new AuthData
        {
            AuthMethods = new List<string> { "otp" },
            Otp = new Otp
            {
                TxnId = txnId,
                OtpValue = otpValue,
                Mobile = mobileNumber,
                Timestamp = DateTime.Now.ToString(Constants.TIMESTAMP_FORMAT)
            }
        };
        Consent = new Consent
        {
            Code = "abha-enrollment",
            Version = "1.4"
        };
    }
}
public class AuthData
{
    public List<string> AuthMethods { get; set; }
    public Otp Otp { get; set; }
}

public class Otp
{
    public string TxnId { get; set; }
    public  string Timestamp { get; set; }
    public string OtpValue { get; set; }
    public string Mobile { get; set; }
}

public class Consent
{
    public string Code { get; set; }
    public string Version { get; set; }
}

