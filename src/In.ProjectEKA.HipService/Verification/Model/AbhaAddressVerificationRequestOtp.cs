using System;

namespace In.ProjectEKA.HipService.Verification.Model;

public class AbhaAddressVerificationRequestOtp
{
    public string AbhaAddress{ get; }
    public AuthMode? AuthMethod { get; }

    public AbhaAddressVerificationRequestOtp(string abhaAddress, AuthMode authMethod)
    {
        if (string.IsNullOrWhiteSpace(abhaAddress))
        {
            throw new ArgumentException("Abha Address must be provided.");
        }
        AbhaAddress = abhaAddress;
        AuthMethod = authMethod;
    }
}