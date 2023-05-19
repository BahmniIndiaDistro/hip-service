namespace In.ProjectEKA.HipService.Creation.Model
{
    public class TokenResponse
    {
        public string token;

        public string refreshToken;

        public TokenResponse(string token, string refreshToken)
        {
            this.token = token;
            this.refreshToken = refreshToken;
        }
    }
}