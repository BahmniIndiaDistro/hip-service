using System;

namespace In.ProjectEKA.HipService.Verification.Model;

public class VerificationRequestOtp
{
    public string AbhaNumber { get; }
    public string MobileNumber { get; }
    public AuthMode? AuthMethod { get; }

    public VerificationRequestOtp(string abhaNumber, string mobileNumber, AuthMode authMethod)
    {
        if (string.IsNullOrWhiteSpace(abhaNumber) && string.IsNullOrWhiteSpace(mobileNumber) ||
            !string.IsNullOrWhiteSpace(abhaNumber) && !string.IsNullOrWhiteSpace(mobileNumber))
        {
            throw new ArgumentException("Either AbhaNumber or MobileNumber or Abha Address must be provided.");
        }
        AbhaNumber = abhaNumber;
        MobileNumber = mobileNumber;
        AuthMethod = authMethod;
    }
}