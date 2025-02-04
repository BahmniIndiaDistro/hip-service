using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Link.Model
{
    public class GatewayNotificationContextRepresentation
    {
        public NotificationContext notification { get; }

        public GatewayNotificationContextRepresentation(
            NotificationContext notification)
        {
            this.notification = notification;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}