using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.Link.Model;

public class HipLinkOnNotifyConfirmation
{
    public HipLinkOnNotifyConfirmation(string requestId, DateTime timestamp,
        AddContextsAcknowledgement acknowledgement, Error error, Resp response)
    {
        RequestId = requestId;
        Timestamp = timestamp;
        Acknowledgement = acknowledgement;
        Error = error;
        Response = response;
    }

    public string RequestId { get; }
    public DateTime Timestamp { get; }
    public Error Error { get; }
    public Resp Response { get; }
    public AddContextsAcknowledgement Acknowledgement { get; }
}
