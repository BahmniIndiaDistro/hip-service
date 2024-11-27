namespace In.ProjectEKA.HipService.Patient.Model
{
    public class ProfileShareAcknowledgement
    {
        public ProfileShareAcknowledgement(string status, string abhaAddress, ProfileShareAckProfile profile)
        {
            Status = status;
            AbhaAddress = abhaAddress;
            Profile = profile;
        }
        
        public string Status { get; }
        public string AbhaAddress { get; }
        public ProfileShareAckProfile Profile { get; }
    }

    public class ProfileShareAckProfile
    {
        public string Context { get; }
        public string TokenNumber { get; }
        public string Expiry { get; }

        public ProfileShareAckProfile(string context, string tokenNumber, string expiry)
        {
            Context = context;
            TokenNumber = tokenNumber;
            Expiry = expiry;
        }
    }
}