namespace In.ProjectEKA.HipService.Creation.Model
{
    public class ABHACardRequest
    {
        public string token;

        public string tokenType = "Bearer";

        public ABHACardRequest(string token)
        {
            this.token = token;
        }
    }
}