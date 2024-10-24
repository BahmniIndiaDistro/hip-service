namespace In.ProjectEKA.HipService.Verification.Model
{
    public class SearchAbhaAddressRequest
    {
        public string abhaAddress { get; }
        public SearchAbhaAddressRequest(string abhaAddress)
        {
            this.abhaAddress = abhaAddress;
        }
    }
}