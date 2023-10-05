namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateHIdDemoAuthRequest
    {
        public string benefitName;
        public string aadharNumber;
        public string name;
        public string gender;
        public string dateOfBirth;
        public string mobileNumber;
        public string districtCode;
        public string stateCode;
        
        public CreateHIdDemoAuthRequest(string benefitName, string aadharNumber, string name, string gender, string dateOfBirth, string mobileNumber, string districtCode, string stateCode)
        {
            this.benefitName = benefitName;
            this.aadharNumber = aadharNumber;
            this.name = name;
            this.gender = gender;
            this.dateOfBirth = dateOfBirth;
            this.mobileNumber = mobileNumber;
            this.districtCode = districtCode;
            this.stateCode = stateCode;
        }
    }
}