using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model;

public class EnrollByAadhaarResponse
{
    public string Message { get; }
    public string TxnId { get; }
    public Tokens Tokens { get; }
    public ABHAProfile ABHAProfile { get; }
    public bool IsNew { get; }

    [JsonConstructor]
    public EnrollByAadhaarResponse(string message, string txnId, Tokens tokens, ABHAProfile abhaProfile, bool isNew)
    {
        Message = message;
        TxnId = txnId;
        Tokens = tokens;
        ABHAProfile = abhaProfile;
        IsNew = isNew;
    }
}

