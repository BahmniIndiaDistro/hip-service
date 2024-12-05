using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class AbhaAddressProfileResponse
{
    public string abhaAddress { get; set; }
    public string fullName { get; set; }
    public string profilePhoto { get; set; }
    public string firstName { get; set; }
    public string middleName { get; set; }
    public string lastName { get; set; }
    public int dayOfBirth { get; set; }
    public int monthOfBirth { get; set; }
    public int yearOfBirth { get; set; }
    public string dateOfBirth { get; set; }
    public string gender { get; set; }
    public string email { get; set; }
    public string mobile { get; set; }
    public string abhaNumber { get; set; }
    public string address { get; set; }
    public string stateName { get; set; }
    public int pinCode { get; set; }
    public int stateCode { get; set; }
    public int districtCode { get; set; }
    public List<string> AuthMethods { get; set; }
    public string status { get; set; }
    public string subDistrictCode { get; set; }
    public string subDistrictName { get; set; }
    public string emailVerified { get; set; }
    public string mobileVerified { get; set; }
    public string kycStatus { get; set; }
    
}