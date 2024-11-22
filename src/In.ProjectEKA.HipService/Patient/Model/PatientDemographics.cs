using System.Collections.Generic;
using Identifier = In.ProjectEKA.HipService.UserAuth.Model.Identifier;

namespace In.ProjectEKA.HipService.Patient.Model
{
    public class PatientDemographics
    {
        public string AbhaAddress { get; }
        public string AbhaNumber { get; }
        public string Name { get; }
        public string Gender { get; }
        public Address Address { get; }
        public int YearOfBirth { get; }
        public int? DayOfBirth { get; }
        public int? MonthOfBirth { get; }
        public string PhoneNumber { get; }

        public PatientDemographics(string name,
            string gender,
            string abhaAddress,
            Address address,
            int yearOfBirth,
            int? dayOfBirth,
            int? monthOfBirth,
            string abhaNumber,
            string phoneNumber)
        {
            Name = name;
            Gender = gender;
            AbhaAddress = abhaAddress;
            Address = address;
            YearOfBirth = yearOfBirth;
            DayOfBirth = dayOfBirth;
            MonthOfBirth = monthOfBirth;
            PhoneNumber = phoneNumber;
            AbhaNumber = abhaNumber;
        }
    }
}