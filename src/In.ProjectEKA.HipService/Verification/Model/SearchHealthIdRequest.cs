namespace In.ProjectEKA.HipService.Verification.Model
{
    public class SearchHealthIdRequest
    {
        public string healthId { get; }
        public string yearOfBirth { get; }
        
        public SearchHealthIdRequest(string healthId, string yearOfBirth)
        {
            this.healthId = healthId;
            this.yearOfBirth = yearOfBirth;
        }
    }
}