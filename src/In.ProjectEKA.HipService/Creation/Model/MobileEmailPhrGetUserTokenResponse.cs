using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class MobileEmailPhrGetUserTokenResponse
    {
        public string token;

        public string refreshToken;

        public string phrAdress;

        public string firstName;

        [JsonConstructor]
        public MobileEmailPhrGetUserTokenResponse(string token, string refreshToken, string phrAdress, string firstName)
        {
            this.token = token;
            this.refreshToken = refreshToken;
            this.phrAdress = phrAdress;
            this.firstName = firstName;
        }
    }
}