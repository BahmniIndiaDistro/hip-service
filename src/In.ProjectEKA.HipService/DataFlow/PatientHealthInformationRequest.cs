namespace In.ProjectEKA.HipService.DataFlow
{
    using System;

    public class PatientHealthInformationRequest
    {
        public PatientHealthInformationRequest(string transactionId,
            HIRequest hiRequest)
        {
            TransactionId = transactionId;
            HiRequest = hiRequest;
        }

        public string TransactionId { get; }
        public HIRequest HiRequest { get; }
    }
}