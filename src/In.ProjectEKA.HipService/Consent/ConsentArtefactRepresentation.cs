namespace In.ProjectEKA.HipService.Consent
{
    using System;
    using Model;

    public class ConsentArtefactRepresentation
    {
        public ConsentArtefactRepresentation(Notification notification)
        {
            Notification = notification;
        }

        public Notification Notification { get; }
    }
}