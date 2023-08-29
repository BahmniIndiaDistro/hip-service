namespace In.ProjectEKA.HipService.Verification.Model
{
    public class MobileLinkedHid
    {
        public string healthIdNumber { get; }
        public string healthId { get; }
        public string name { get; }
        
        public MobileLinkedHid(string healthIdNumber, string healthId, string name)
        {
            this.healthIdNumber = healthIdNumber;
            this.healthId = healthId;
            this.name = name;
        }
        
    }
}