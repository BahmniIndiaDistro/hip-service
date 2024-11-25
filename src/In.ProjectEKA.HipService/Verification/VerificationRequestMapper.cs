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
        if (verificationRequestOtp.AbhaNumber != null && verificationRequestOtp.MobileNumber == null)
        {
            string encryptedAbhaNumber = EncryptionService.Encrypt(verificationRequestOtp.AbhaNumber);
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
                encryptedAbhaNumber,
                otpSystem
            );
        }

        if (verificationRequestOtp.MobileNumber != null && verificationRequestOtp.AbhaNumber == null)
        {
            string encryptedMobileNumber = EncryptionService.Encrypt(verificationRequestOtp.MobileNumber);
            return new ABHALoginRequestOTP(
                new List<ABHAScope> { ABHAScope.ABHA_LOGIN, ABHAScope.MOBILE_VERIFY },
                ABHALoginHint.MOBILE,
                encryptedMobileNumber,
                OTPSystem.ABDM
            );
        }

        throw new ArgumentException("Either AbhaNumber or MobileNumber should be present and not both");
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