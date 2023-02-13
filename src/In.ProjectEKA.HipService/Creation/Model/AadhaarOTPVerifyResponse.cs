using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class AadhaarOTPVerifyResponse
    {
        public AadhaarOTPVerifyResponse(string photo, string name, string gender, string birthdate, string careOf,
            string house, string street, string landmark, string locality, string villageTownCity, string subDist,
            string district, string state, string pincode, string postOffice, string email, string phone, string aadhaar,
            string healthIdNumber, JwtToken jwtResponse, string txnId)
        {
            this.photo = photo;
            this.name = name;
            this.gender = gender;
            this.birthdate = birthdate;
            this.careOf = careOf;
            this.house = house;
            this.street = street;
            this.landmark = landmark;
            this.locality = locality;
            this.villageTownCity = villageTownCity;
            this.subDist = subDist;
            this.district = district;
            this.state = state;
            this.pincode = pincode;
            this.postOffice = postOffice;
            this.email = email;
            this.phone = phone;
            this.aadhaar = aadhaar;
            this.healthIdNumber = healthIdNumber;
            this.jwtResponse = jwtResponse;
            this.txnId = txnId;
        }

        public string txnId { get; }
        public string photo { get; }
        public string name { get;  }
        public string gender { get; }
        public string birthdate { get; }
        public string careOf { get;  }
        public string house { get; }
        public string street { get;  }
        public string landmark { get; }
        public string locality { get; }
        public string villageTownCity { get;  }
        public string subDist { get; }
        public string district { get;  }
        public string state { get; }
        public string pincode { get;  }
        public string postOffice { get; }
        public string email { get; }
        public string phone { get; set; }
        public string aadhaar { get; }
        public string healthIdNumber { get;  }
        public JwtToken jwtResponse { get; }
        public List<string> phrAddress { get; set; }
        public string healthId { get; set; }
    }

    public class JwtToken
    {
        public string token;

        public JwtToken(string token)
        {
            this.token = token;
        }
    }
}