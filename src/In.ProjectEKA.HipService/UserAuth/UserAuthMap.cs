using System;
using System.Collections.Generic;

namespace In.ProjectEKA.HipService.UserAuth
{
    public static class UserAuthMap
    {
        public static Dictionary<Guid, string> RequestIdToAuthModes = new Dictionary<Guid, string>();
        public static Dictionary<Guid, string> RequestIdToTransactionIdMap = new Dictionary<Guid, string>();
        public static Dictionary<Guid, string> RequestIdToAccessToken = new Dictionary<Guid, string>();

        public static Dictionary<string, string> HealthIdToTransactionId = new Dictionary<string, string>()
        {
            {
                "hinapatel@sbx", "121391739719837"
            }
        };
    }
}