using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarDemoAuthRequest
    {
        public string aadhaarNumber;
        public string name;
        public string gender;
        public string dateOfBirth;
        public string district;
        public string state;
        public string mobileNumber;

        [JsonConstructor]
        public AadhaarDemoAuthRequest(string aadhaarNumber, string name, string gender, string dateOfBirth, string district, string state, string mobileNumber)
        {
            this.aadhaarNumber = aadhaarNumber;
            this.name = name;
            this.gender = gender;
            this.dateOfBirth = dateOfBirth;
            this.district = district;
            this.state = state;
            this.mobileNumber = mobileNumber;
        }

    }
}