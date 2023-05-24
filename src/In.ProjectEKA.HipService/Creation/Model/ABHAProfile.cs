using System.Collections.Generic;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class ABHAProfile
    {
        [JsonConstructor]
        public ABHAProfile(string healthIdNumber, string healthId, string profilePhoto, string kycPhoto, string name, string firstName,
            string middleName, string lastName, string gender, string dayOfBirth, string monthOfBirth, string yearOfBirth, string address, string districtCode, string districtName, string stateCode, string stateName, string subDistrictCode, string subDistrictName, string townCode, string townName, string villageCode, string villageName, string wardCode, string wardName, string pincode, string email, string mobile, List<string> authMethods, object tags, List<string> phrAddress, bool @new)
        {
            this.healthIdNumber = healthIdNumber;
            this.healthId = healthId;
            this.profilePhoto = profilePhoto;
            this.kycPhoto = kycPhoto;
            this.name = name;
            this.firstName = firstName;
            this.middleName = middleName;
            this.lastName = lastName;
            this.gender = gender;
            this.dayOfBirth = dayOfBirth;
            this.monthOfBirth = monthOfBirth;
            this.yearOfBirth = yearOfBirth;
            this.address = address;
            this.districtCode = districtCode;
            this.districtName = districtName;
            this.stateCode = stateCode;
            this.stateName = stateName;
            this.subDistrictCode = subDistrictCode;
            this.subDistrictName = subDistrictName;
            this.townCode = townCode;
            this.townName = townName;
            this.villageCode = villageCode;
            this.villageName = villageName;
            this.wardCode = wardCode;
            this.wardName = wardName;
            this.pincode = pincode;
            this.email = email;
            this.mobile = mobile;
            this.authMethods = authMethods;
            this.tags = tags;
            this.phrAddress = phrAddress;
            this.@new = @new;
        }

        public ABHAProfile(string healthId)
        {
            this.healthId = healthId;
        }

        public string healthIdNumber { get; }
        public string healthId { get; }
        public bool @new { get; }
        public string profilePhoto { get; }
        public string kycPhoto { get; }
        public string name { get;  }
        public string firstName { get; }
        public string middleName { get; }
        public string lastName { get;  }
        public string gender { get; }
        public string dayOfBirth { get;  }
        public string monthOfBirth { get; }
        public string yearOfBirth { get; }
        public string address { get; }
        public string districtCode { get;  }
        public string districtName { get; }
        public string stateCode { get;  }
        public string stateName { get; }
        public string subDistrictCode { get;  }
        public string subDistrictName { get; }
        public string townCode { get;  }
        public string townName { get; }
        public string villageCode { get;  }
        public string villageName { get; }
        public string wardCode { get;  }
        public string wardName { get; }
        public string pincode { get;  }
        public string email { get; }
        public string mobile { get;  }
        public List<string> authMethods { get; }
        public object tags { get; }
        public List<string> phrAddress { get; }
    }
}