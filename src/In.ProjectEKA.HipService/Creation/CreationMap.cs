using System.Collections.Generic;
using In.ProjectEKA.HipService.Creation.Model;

namespace In.ProjectEKA.HipService.Creation
{
    public static class CreationMap
    {
        public static Dictionary<string, string> TxnDictionary = new Dictionary<string, string>();
        
        public static Dictionary<string, string> HealthIdNumberDictionary = new Dictionary<string, string>();
        
        public static Dictionary<string, TokenRequest> HealthIdNumberTokenDictionary = new Dictionary<string, TokenRequest>();
        
        public static Dictionary<string, string> HealthIdTokenDictionary = new Dictionary<string, string>();
        
        public static Dictionary<string, string> VerifiedMobileTokenDictionary = new Dictionary<string, string>();
        
        public static Dictionary<string, List<string>> HealthIdLoginScopeDictionary = new Dictionary<string, List<string>>();
    }
}