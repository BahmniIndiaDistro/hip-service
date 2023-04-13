using System.Collections.Generic;
using Hl7.Fhir.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class Demographics
    {
        public string name { get; }
        public string gender { get; }
        public string dateOfBirth { get; }
    
        public Identifier identifier { get; }

        public Demographics(string name, string gender, string dateOfBirth, Identifier identifier)
        {
            this.name = name;
            this.gender = gender;
            this.dateOfBirth = dateOfBirth;
            this.identifier = identifier;
        }
    }
}