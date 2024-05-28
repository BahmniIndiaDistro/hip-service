using System;
using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Link.Model
{
    public class NotificationContext
    {
        public NotificationPatientContext patient { get; }

        public NotificationCareContext careContext { get; }

        public List<string> hiTypes { get; }

        public string date { get; }

        public NotificationContextHip hip { get; }


        public NotificationContext(NotificationPatientContext patient, NotificationCareContext careContext,
            List<string> hiTypes, string dateTime, NotificationContextHip hip)
        {
            this.patient = patient;
            this.careContext = careContext;
            this.hiTypes = hiTypes;
            date = dateTime;
            this.hip = hip;
        }
    }
}