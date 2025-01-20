using System.Collections.Generic;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    public class CareContextRepresentation
    {
        
        public CareContextRepresentation(string referenceNumber, string display)
        {
            ReferenceNumber = referenceNumber;
            Display = display;
        }
        
        [JsonConstructor]
        public CareContextRepresentation(string referenceNumber, string display, string type,
            IEnumerable<HiType> hiTypes)
        {
            ReferenceNumber = referenceNumber;
            Display = display;
            Type = type;
            HiTypes = hiTypes;
        }

        public string ReferenceNumber { get; }

        public string Display { get; }
        public string Type { get; }
        
        public IEnumerable<HiType> HiTypes { get; } 
    }
}