using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipService.Common.Model;

namespace In.ProjectEKA.HipService.Verification.Model;

public class ABHALoginRequestOTP
{

    public List<string> Scope { get; }
    public string LoginHint { get; }
    public string LoginId { get; }
    public string OtpSystem { get; }
    
    public ABHALoginRequestOTP(List<ABHAScope> scope, ABHALoginHint loginHint, string loginId, OTPSystem otpSystem)
    {
        Scope = scope.Select(s => s.Value).ToList();
        LoginHint = loginHint.Value;
        LoginId = loginId;
        OtpSystem = otpSystem.Value;
    }
    
}