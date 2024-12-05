using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class VerificationVerifyOtpResponse
{
    public string TxnId { get; set; }
    public string AuthResult { get; set; }
    public string Message { get; set; }
    public List<Account> Accounts { get; set; }
}