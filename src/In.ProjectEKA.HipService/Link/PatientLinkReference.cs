namespace In.ProjectEKA.HipService.Link
{
    using System.Collections.Generic;
    using HipLibrary.Patient.Model;

    public class PatientLinkReference
    {
        public PatientLinkReference(string referenceNumber, IEnumerable<CareContextEnquiry> careContexts, string hiType, int count)
        {
            ReferenceNumber = referenceNumber;
            CareContexts = careContexts;
            HiType = hiType;
            Count = count;
        }

        public string ReferenceNumber { get; }

        public IEnumerable<CareContextEnquiry> CareContexts { get; }
        
        public string HiType { get; }
        
        public int Count { get; }
    }
}