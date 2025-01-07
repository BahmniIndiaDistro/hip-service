using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Link
{
    public class LinkReferenceRequest
    {
        public LinkReferenceRequest(string transactionId, string abhaAddress, IEnumerable<PatientLinkReference> patient)
        {
            TransactionId = transactionId;
            AbhaAddress = abhaAddress;
            Patient = patient;
        }

        public string TransactionId { get; }
        
        public string AbhaAddress { get; }
        
        public IEnumerable<PatientLinkReference> Patient { get; }
    }
}