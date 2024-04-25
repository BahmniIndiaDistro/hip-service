namespace In.ProjectEKA.HipService.Link.Model
{
    public class PatientAbhaIdentifier
    {
        public string abhaNumber { get; }
        public string abhaAddress { get; }

        public PatientAbhaIdentifier(string abhaNumber, string abhaAddress)
        {
            this.abhaNumber = abhaNumber;
            this.abhaAddress = abhaAddress;
        }
    }   
}