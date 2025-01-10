namespace In.ProjectEKA.HipService.Gateway.Model
{
    using System;
    using DataFlow;

    public class GatewayDataNotificationRequest
    {
        public GatewayDataNotificationRequest(DataFlowNotificationRequest notification)
        {
            Notification = notification;
        }
        
        public DataFlowNotificationRequest Notification { get; }
    }
}