using System.Collections.Generic;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model;

public class ABHAProfile
{
    public string FirstName { get; }
    public string MiddleName { get; }
    public string LastName { get; }
    public string Dob { get; }
    public string Gender { get; }
    public string Photo { get; }
    public string Mobile { get; }
    public string Email { get; }
    public IReadOnlyList<string> PhrAddress { get; }
    public string Address { get; }
    public string DistrictCode { get; }
    public string StateCode { get; }
    public string PinCode { get; }
    public string AbhaType { get; }
    public string StateName { get; }
    public string DistrictName { get; }
    public string ABHANumber { get; }
    public string AbhaStatus { get; }

    [JsonConstructor]
    public ABHAProfile(string firstName, string middleName, string lastName, string dob, string gender, string photo, string mobile, string email, IReadOnlyList<string> phrAddress, string address, string districtCode, string stateCode, string pinCode, string abhaType, string stateName, string districtName, string abhaNumber, string abhaStatus)
    {
        FirstName = firstName;
        MiddleName = middleName;
        LastName = lastName;
        Dob = dob;
        Gender = gender;
        Photo = photo;
        Mobile = mobile;
        Email = email;
        PhrAddress = phrAddress;
        Address = address;
        DistrictCode = districtCode;
        StateCode = stateCode;
        PinCode = pinCode;
        AbhaType = abhaType;
        StateName = stateName;
        DistrictName = districtName;
        ABHANumber = abhaNumber;
        AbhaStatus = abhaStatus;
    }
}