using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.SmsNotification.Model
{
    public class OnSmsNotifyRequest
    {
        public string status { get; }
        public Error error { get; }
        public Resp response { get; }

        public OnSmsNotifyRequest(string status, Error error, Resp response)
        {
            this.status = status;
            this.error = error;
            this.response = response;
        }
    }
}