namespace In.ProjectEKA.HipService.Link
{
    using System;
    using HipLibrary.Patient.Model;
    using Model;

    public class HipLinkContextConfirmation
    {
        public HipLinkContextConfirmation(string abhaAddress, string status, Error error, Resp response)
        {
            AbhaAddress = abhaAddress;
            Status = status;
            Error = error;
            Response = response;
        }

        public string AbhaAddress { get; }
        public string Status { get; }
        public Error Error { get; }
        public Resp Response { get; }
       
    }
}