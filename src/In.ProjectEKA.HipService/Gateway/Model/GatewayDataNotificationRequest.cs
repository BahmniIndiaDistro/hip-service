namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using DataFlow;

    public class GatewayDataNotificationRequest
    {
        public GatewayDataNotificationRequest(Guid requestId, string timestamp,
            DataFlowNotificationRequest notification)
        {
            RequestId = requestId;
            Timestamp = timestamp;
            Notification = notification;
        }

        public Guid RequestId { get; }
        public string Timestamp { get; }
        public DataFlowNotificationRequest Notification { get; }
    }
}