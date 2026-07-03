using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    /// <summary>
    /// Response from V3 search ABHA by mobile: txnId and list of masked ABHA with name, gender, index.
    /// </summary>
    public class SearchAbhaByMobileResponse
    {
        public string txnId { get; set; }
        public List<AbhaSearchEntry> abhaList { get; set; }
    }

    public class AbhaSearchEntry
    {
        public int index { get; set; }
        public string abhaNumber { get; set; }
        public string name { get; set; }
        public string gender { get; set; }
    }
}
