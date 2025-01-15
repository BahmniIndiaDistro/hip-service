namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    using System.Collections.Generic;

    public class LinkConfirmationRepresentation
    {
        public LinkConfirmationRepresentation()
        {
        }

        public LinkConfirmationRepresentation(string referenceNumber, string display,
            IEnumerable<CareContextRepresentation> careContexts, string hiType, int count)
        {
            ReferenceNumber = referenceNumber;
            Display = display;
            CareContexts = careContexts;
            HiType = hiType;
            Count = count;
        }

        public string ReferenceNumber { get; }

        public string Display { get; }

        public IEnumerable<CareContextRepresentation> CareContexts { get; }
        
        public string HiType { get; }
        
        public int Count { get; }
    }
}