using System;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.Patient.Model
{
    public class ProfileShareConfirmation
    {
        public ProfileShareConfirmation(ProfileShareAcknowledgement acknowledgement, Error error, Resp resp)
        {
            Acknowledgement = acknowledgement;
            Error = error;
            Response = resp;
        }
        public Error Error { get; }
        public Resp Response { get; }
        public ProfileShareAcknowledgement Acknowledgement { get; }
    }
}