using System;
using System.Collections.Generic;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Verification.Model;

namespace In.ProjectEKA.HipService.Verification;

public static class VerificationRequestMapper
{
    public static ABHALoginRequestOTP mapAbhaLoginOTPRequest(VerificationRequestOtp verificationRequestOtp)
    {
        string encryptedIdentifier = EncryptionService.Encrypt(verificationRequestOtp.Identifier);
        if (verificationRequestOtp.IdentifierType.Equals(IdentifierType.ABHA_NUMBER))
        {
            List<ABHAScope> scopes = new List<ABHAScope>();
            OTPSystem otpSystem;
            if (verificationRequestOtp.AuthMethod == AuthMode.AADHAAR_OTP)
            {
                scopes = new List<ABHAScope> { ABHAScope.ABHA_LOGIN, ABHAScope.AADHAAR_VERIFY };
                otpSystem = OTPSystem.AADHAAR;
            }
            else if (verificationRequestOtp.AuthMethod == AuthMode.MOBILE_OTP)
            {
                scopes = new List<ABHAScope> { ABHAScope.ABHA_LOGIN, ABHAScope.MOBILE_VERIFY };
                otpSystem = OTPSystem.ABDM;
            }
            else
            {
                throw new ArgumentException("Invalid AuthMethod");
            }

            return new ABHALoginRequestOTP(
                scopes,
                ABHALoginHint.ABHA_NUMBER,
                encryptedIdentifier,
                otpSystem
            );
        }

        if (verificationRequestOtp.IdentifierType.Equals(IdentifierType.MOBILE_NUMBER))
        {
            return new ABHALoginRequestOTP(
                new List<ABHAScope> { ABHAScope.ABHA_LOGIN, ABHAScope.MOBILE_VERIFY },
                ABHALoginHint.MOBILE,
                encryptedIdentifier,
                OTPSystem.ABDM
            );
        }
        if (verificationRequestOtp.IdentifierType.Equals(IdentifierType.AADHAAR_NUMBER))
        {
            return new ABHALoginRequestOTP(
                new List<ABHAScope> { ABHAScope.ABHA_LOGIN, ABHAScope.AADHAAR_VERIFY },
                ABHALoginHint.AADHAAR,
                encryptedIdentifier,
                OTPSystem.AADHAAR
            );
        }

        throw new ArgumentException("Invalid Identifier Type");
    }

    public static ABHALoginRequestOTP mapAbhaAddressLoginRequestOTP(
        AbhaAddressVerificationRequestOtp abhaAddressVerificationRequestOtp)
    {
        if (abhaAddressVerificationRequestOtp.AbhaAddress != null)
        {
            string encryptedAbhaAddress = EncryptionService.Encrypt(abhaAddressVerificationRequestOtp.AbhaAddress);
            List<ABHAScope> scopes = new List<ABHAScope>();
            OTPSystem otpSystem;
            if (abhaAddressVerificationRequestOtp.AuthMethod == AuthMode.AADHAAR_OTP)
            {
                scopes = new List<ABHAScope> { ABHAScope.ABHA_ADDRESS_LOGIN, ABHAScope.AADHAAR_VERIFY };
                otpSystem = OTPSystem.AADHAAR;
            }
            else if (abhaAddressVerificationRequestOtp.AuthMethod == AuthMode.MOBILE_OTP)
            {
                scopes = new List<ABHAScope> { ABHAScope.ABHA_ADDRESS_LOGIN, ABHAScope.MOBILE_VERIFY };
                otpSystem = OTPSystem.ABDM;
            }
            else
            {
                throw new ArgumentException("Invalid AuthMethod");
            }

            return new ABHALoginRequestOTP(
                scopes,
                ABHALoginHint.ABHA_Address,
                encryptedAbhaAddress,
                otpSystem
            );
        }

        throw new ArgumentException("Abha Address is missing.");
        
    }
}