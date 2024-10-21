using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarOTPVerifyAndCreateABHAResponse
    {
        public string Message { get; }
        public ABHAProfile ABHAProfile { get; }
        public bool IsNew { get; }

        public AadhaarOTPVerifyAndCreateABHAResponse(string message, ABHAProfile abhaProfile, bool isNew)
        {
            Message = message;
            ABHAProfile = abhaProfile;
            IsNew = isNew;
        }
    }
}