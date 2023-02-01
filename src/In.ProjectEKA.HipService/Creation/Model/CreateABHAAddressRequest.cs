namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAAddressRequest
    {
        public string phrAddress;
        public string preferred;

        public CreateABHAAddressRequest(string phrAddress, string preferred)
        {
            this.phrAddress = phrAddress;
            this.preferred = preferred;
        }
    }
}