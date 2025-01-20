using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.SmsNotification.Model
{
    public class GatewaySmsNotifyRequestRepresentation
    {
        public SmsNotification notification { get; }

        public GatewaySmsNotifyRequestRepresentation(SmsNotification notification)
        {
            this.notification = notification;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}