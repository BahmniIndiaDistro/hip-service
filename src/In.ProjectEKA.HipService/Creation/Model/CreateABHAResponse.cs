using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAResponse
    {
        public CreateABHAResponse(string healthIdNumber,string mobile)
        {
            this.healthIdNumber = healthIdNumber;
            this.mobile = mobile;
        }

        public string healthIdNumber { get; }
        public string mobile { get;  }
    }
}