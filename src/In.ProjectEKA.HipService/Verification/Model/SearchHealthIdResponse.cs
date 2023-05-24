using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    public class SearchHealthIdResponse
    {
        public List<string> authMethods { get; }
        public string status { get; }
        
        public SearchHealthIdResponse(List<string> authMethods, string status)
        {
            this.authMethods = authMethods;
            this.status = status;
        }
    }
}