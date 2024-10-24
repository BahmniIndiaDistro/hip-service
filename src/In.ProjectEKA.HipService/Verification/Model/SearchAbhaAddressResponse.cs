using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model
{
    public class SearchAbhaAddressResponse
    {
        public string HealthIdNumber { get; set; }
        public string AbhaAddress { get; set; }
        public List<string> AuthMethods { get; set; }
        public List<string> BlockedAuthMethods { get; set; }
        public string Status { get; set; }
        public string Message { get; set; }
        public string FullName { get; set; }
        public string Mobile { get; set; }
        
    }
}