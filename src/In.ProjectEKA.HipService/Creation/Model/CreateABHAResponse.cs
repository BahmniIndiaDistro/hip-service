using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAResponse
    {
        public CreateABHAResponse(string healthIdNumber,string mobile, string token, string refreshToken)
        {
            this.healthIdNumber = healthIdNumber;
            this.mobile = mobile;
            this.token = token;
            this.refreshToken = refreshToken;
        }

        public string healthIdNumber { get; }
        public string mobile { get;  }
        public string token { get; }
        public string refreshToken { get; }
    }
}