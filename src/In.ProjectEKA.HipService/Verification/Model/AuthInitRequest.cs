namespace In.ProjectEKA.HipService.Verification.Model
{
    public class AuthInitRequest
    {
        public string healthid { get; }
        public string authMethod { get; }
        
        public AuthInitRequest(string healthid, string authMethod)
        {
            this.healthid = healthid;
            this.authMethod = authMethod;
        }
    }
}