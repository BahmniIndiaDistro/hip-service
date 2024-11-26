using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class AbhaAddressLoginVerifyOTPResponse
{
    public string authResult { get; set; }
    public string message { get; set; }
    public List<User> users { get; set; }
    public Token tokens { get; set; }
}

public class User
{
    public string abhaAddress { get; set; }
    public string fullName { get; set; }
    public string profilePhoto { get; set; }
    public string abhaNumber { get; set; }
    public string status { get; set; }
    public string kycStatus { get; set; }
    
}
public class Token
{
    public string token { get; set; }
    public int expiresIn { get; set; }
    public string refreshToken { get; set; }
    public int refreshExpiresIn { get; set; }
    
}