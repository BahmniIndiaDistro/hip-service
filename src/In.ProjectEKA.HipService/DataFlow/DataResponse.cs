namespace In.ProjectEKA.HipService.DataFlow
{
    using System.Collections.Generic;

    public class DataResponse
    {
        public DataResponse(string transactionId, IEnumerable<Entry> entries, KeyMaterial keyMaterial)
        {
            pageNumber = 0;
            pageCount = 1;
            TransactionId = transactionId;
            Entries = entries;
            KeyMaterial = keyMaterial;
        }

        public int pageNumber { get; set; }
        public int pageCount { get; set; }
        public string TransactionId { get; }

        public IEnumerable<Entry> Entries { get; }

        public KeyMaterial KeyMaterial { get; }
    }
}