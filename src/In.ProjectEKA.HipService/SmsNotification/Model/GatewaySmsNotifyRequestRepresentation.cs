using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.SmsNotification.Model
{
    public class GatewaySmsNotifyRequestRepresentation
    {
        public Guid requestId { get; }
        public string timestamp { get; }
        public SmsNotification notification { get; }

        public GatewaySmsNotifyRequestRepresentation(Guid requestId, string timestamp, SmsNotification notification)
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