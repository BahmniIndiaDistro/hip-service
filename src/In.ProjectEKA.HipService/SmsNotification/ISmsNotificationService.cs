using System;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.SmsNotification.Model;

namespace In.ProjectEKA.HipService.SmsNotification
{
    public interface ISmsNotificationService
    {
        public Tuple<GatewaySmsNotifyRequestRepresentation, ErrorRepresentation> SmsNotifyRequest(
             SmsNotifyRequest smsNotifyRequest, BahmniConfiguration bahmniConfiguration);
        
    }
}