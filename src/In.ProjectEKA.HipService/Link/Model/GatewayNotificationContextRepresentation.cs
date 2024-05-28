using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Link.Model
{
    public class GatewayNotificationContextRepresentation
    {
        public Guid requestId { get; }
        public string timestamp { get; }
        public NotificationContext notification { get; }

        public GatewayNotificationContextRepresentation(Guid requestId, string timestamp,
            NotificationContext notification)
        {
            this.requestId = requestId;
            this.timestamp = timestamp;
            this.notification = notification;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}