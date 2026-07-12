using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    /// <summary>
    /// Request for V3 API: Find ABHA number using mobile number.
    /// Body: scope (e.g. ["search-abha"]), mobile (RSA encrypted).
    /// </summary>
    public class SearchAbhaByMobileRequest
    {
        public List<string> scope { get; set; }
        public string mobile { get; set; }
    }
}
