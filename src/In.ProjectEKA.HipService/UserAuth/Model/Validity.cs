using System;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class Validity
    {
        public string purpose { get; }
        public Requester requester { get; }
        public DateTime expiry { get; }
        public string limit { get; }

        public Validity(string purpose, Requester requester, DateTime expiry, string limit)
        {
            this.purpose = purpose;
            this.requester = requester;
            this.expiry = expiry;
            this.limit = limit;
        }
    }
}