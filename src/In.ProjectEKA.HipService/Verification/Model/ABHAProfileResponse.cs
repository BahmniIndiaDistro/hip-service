using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Verification.Model;

public class ABHAProfileResponse
{
    public string ABHANumber { get; set; }
    public string PreferredAbhaAddress { get; set; }
    public string Mobile { get; set; }
    public string FirstName { get; set; }
    public string MiddleName { get; set; }
    public string LastName { get; set; }
    public string Name { get; set; }
    public string YearOfBirth { get; set; }
    public string DayOfBirth { get; set; }
    public string MonthOfBirth { get; set; }
    public string Gender { get; set; }
    public string Email { get; set; }
    public string ProfilePhoto { get; set; }
    public string StateCode { get; set; }
    public string DistrictCode { get; set; }
    public string SubDistrictCode { get; set; }
    public string VillageCode { get; set; }
    public string TownCode { get; set; }
    public string WardCode { get; set; }
    public string Pincode { get; set; }
    public string Address { get; set; }
    public string KycPhoto { get; set; }
    public string StateName { get; set; }
    public string DistrictName { get; set; }
    public string SubdistrictName { get; set; }
    public string VillageName { get; set; }
    public string TownName { get; set; }
    public string WardName { get; set; }
    public List<string> AuthMethods { get; set; }
    public Dictionary<string, string> Tags { get; set; }
    public bool KycVerified { get; set; }
    public string VerificationStatus { get; set; }
    public string VerificationType { get; set; }
    public bool EmailVerified { get; set; }
}