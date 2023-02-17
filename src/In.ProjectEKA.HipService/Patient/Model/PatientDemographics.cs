using System.Collections.Generic;
using Identifier = In.ProjectEKA.HipService.UserAuth.Model.Identifier;

namespace In.ProjectEKA.HipService.Patient.Model
{
    public class PatientDemographics
    {
        public string HealthId { get; }
        public string HealthIdNumber { get; }
        public string Name { get; }
        public string Gender { get; }
        public Address Address { get; }
        public int YearOfBirth { get; }
        public int? DayOfBirth { get; }
        public int? MonthOfBirth { get; }
        public List<Identifier> Identifiers { get; }

        public PatientDemographics(string name,
            string gender,
            string healthId,
            Address address,
            int yearOfBirth,
            int? dayOfBirth,
            int? monthOfBirth,
            List<Identifier> identifiers, string healthIdNumber)
        {
            Name = name;
            Gender = gender;
            HealthId = healthId;
            Address = address;
            YearOfBirth = yearOfBirth;
            DayOfBirth = dayOfBirth;
            MonthOfBirth = monthOfBirth;
            Identifiers = identifiers;
            HealthIdNumber = healthIdNumber;
        }
    }
}