namespace In.ProjectEKA.HipService.Verification.Model
{
    public class AuthInitRequest
    {
        public string healthid { get; }
        public AuthMode authMethod { get; }
        
        public AuthInitRequest(string healthid, AuthMode authMethod)
        {
            this.healthid = healthid;
            this.authMethod = authMethod;
        }
    }
}