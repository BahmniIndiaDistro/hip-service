using System.Collections.Generic;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class AuthConfirmPatient
    {
        public string id { get; }
        public string name { get; }
        public string gender { get; }
        public string yearOfBirth { get; }
        public AuthConfirmAddress address { get; }
        public List<Identifier> identifiers { get; }

        public AuthConfirmPatient(string id, string name, string gender, string yearOfBirth, AuthConfirmAddress address,
            List<Identifier> identifiers)
        {
            this.id = id;
            this.name = name;
            this.gender = gender;
            this.yearOfBirth = yearOfBirth;
            this.address = address;
            this.identifiers = identifiers;
        }
    }
}