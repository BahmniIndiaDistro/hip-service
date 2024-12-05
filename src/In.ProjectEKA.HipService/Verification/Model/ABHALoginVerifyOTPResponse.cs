using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class ABHALoginVerifyOTPResponse
{
    public string TxnId { get; set; }
    public string AuthResult { get; set; }
    public string Message { get; set; }
    public string Token { get; set; }
    public int ExpiresIn { get; set; }
    public string RefreshToken { get; set; }
    public int RefreshExpiresIn { get; set; }
    public List<Account> Accounts { get; set; }
}

public class Account
{
    public string ABHANumber { get; set; }
    public string PreferredAbhaAddress { get; set; }
    public string Name { get; set; }
    public string Gender { get; set; }
    public string Dob { get; set; }
    public string Status { get; set; }
    public string ProfilePhoto { get; set; }
    public bool KycVerified { get; set; }
}
