using System.Collections.Generic;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAAddressSuggestionResponse
{
    public string txnId { get; }
    public List<string> abhaAddressList { get; }

    [JsonConstructor]
    public ABHAAddressSuggestionResponse(string txnId, List<string> abhaAddressList)
    {
        this.txnId = txnId;
        this.abhaAddressList = abhaAddressList;
    }

    public ABHAAddressSuggestionResponse(List<string> abhaAddressList)
    {
        this.abhaAddressList = abhaAddressList;
    }
}