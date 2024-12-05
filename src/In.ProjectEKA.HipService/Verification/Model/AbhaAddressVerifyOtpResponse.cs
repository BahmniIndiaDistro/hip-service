using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class AbhaAddressVerifyOtpResponse
{
    public string AuthResult { get; set; }
    public string Message { get; set; }
    public List<User> Users { get; set; }
}