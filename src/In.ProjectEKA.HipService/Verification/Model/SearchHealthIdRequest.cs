namespace In.ProjectEKA.HipService.Verification.Model
{
    public class SearchHealthIdRequest
    {
        public string healthId { get; }
        public SearchHealthIdRequest(string healthId)
        {
            this.healthId = healthId;
        }
    }
}