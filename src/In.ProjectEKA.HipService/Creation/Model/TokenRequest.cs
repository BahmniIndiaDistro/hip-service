namespace In.ProjectEKA.HipService.Creation.Model
{
    public class TokenRequest
    {
        public string token;

        public string tokenType = "Bearer";

        public TokenRequest(string token)
        {
            this.token = token;
        }
    }
}