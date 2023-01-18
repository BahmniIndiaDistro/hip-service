using System;
using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAResponse
    {
        public CreateABHAResponse(string healthIdNumber, string healthId, string profilePhoto, string kycPhoto, string name, string firstName,
            string middleName, string lastName, string gender, string dayOfBirth, string monthOfBirth, string yearOfBirth, string districtCode, 
            string districtName, string stateCode, string stateName, string pincode, string email, string mobile, string aadhaar, 
            List<string> authMethods, string token, string refreshToken, object tags, bool @new)
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
            this.districtCode = districtCode;
            this.districtName = districtName;
            this.stateCode = stateCode;
            this.stateName = stateName;
            this.pincode = pincode;
            this.email = email;
            this.mobile = mobile;
            this.aadhaar = aadhaar;
            this.authMethods = authMethods;
            this.token = token;
            this.refreshToken = refreshToken;
            this.tags = tags;
            this.@new = @new;
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
        public string districtCode { get;  }
        public string districtName { get; }
        public string stateCode { get;  }
        public string stateName { get; }
        public string pincode { get;  }
        public string email { get; }
        public string mobile { get;  }
        public string aadhaar { get; }
        public List<string> authMethods { get; }
        public string token { get; }
        public string refreshToken { get; }
        public object tags { get; }
    }
}