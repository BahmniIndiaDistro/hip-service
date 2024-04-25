using System;
using System.Collections.Generic;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.AspNetCore.Http;

namespace In.ProjectEKA.HipService.Discovery
{
    public static class DiscoveryReqMap {
        public static Dictionary<string, string> AbhaIdentifierMap = new Dictionary<string, string>();
    }
}