using System.Collections.Generic;
using In.ProjectEKA.HipService.Link.Model;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class HealthIdAuthModeResponse
    {
        public string healthIdNumber;

        public List<Mode> authMethods;

        public string status;

        public List<Mode> blockedAuthMethods;

        public HealthIdAuthModeResponse(string healthIdNumber, List<Mode> authMethods, string status, List<Mode> blockedAuthMethods)
        {
            this.healthIdNumber = healthIdNumber;
            this.authMethods = authMethods;
            this.status = status;
            this.blockedAuthMethods = blockedAuthMethods;
        }
    }
}