namespace In.ProjectEKA.HipService.Creation.Model
{
    public class TokenResponse
    {
        public string token;

        public int expiresIn;

        public string refreshToken;

        public int refreshExpiresIn;

        public TokenResponse(string token, int expiresIn, string refreshToken, int refreshExpiresIn)
        {
            this.token = token;
            this.expiresIn = expiresIn;
            this.refreshToken = refreshToken;
            this.refreshExpiresIn = refreshExpiresIn;
        }
    }
}