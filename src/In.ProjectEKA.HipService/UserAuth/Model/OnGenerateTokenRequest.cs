using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model;

public class OnGenerateTokenRequest
{
    public string AbhaAddress { get; }
    
    public string LinkToken { get; }
    
    public Resp Response { get; }
    
    public Error Error { get; }
    
    public OnGenerateTokenRequest(string abhaAddress, string linkToken, Resp response, Error error)
    {
        AbhaAddress = abhaAddress;
        LinkToken = linkToken;
        Response = response;
        Error = error;
    }
    
}