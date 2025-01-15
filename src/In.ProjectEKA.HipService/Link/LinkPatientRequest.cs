namespace In.ProjectEKA.HipService.Link
{
    public class LinkPatientRequest
    {
        public LinkPatientRequest(LinkConfirmation confirmation)
        {
            Confirmation = confirmation;
        }

        public LinkConfirmation Confirmation { get; }
    }
}