using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class PhrAddressLinkResponse
    {
        public string success;

        public PhrAddressLinkResponse(string success)
        {
            this.success = success;
        }
    }
}