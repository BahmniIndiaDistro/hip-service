namespace In.ProjectEKA.HipService.OpenMrs
{
    public class OpenMrsConfiguration
    {
        public string Url { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }
        
        
        public string PhoneNumber { get; set; }
        public int PatientQueueTimeLimit { get; set; }

    }
}