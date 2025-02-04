using System;
using System.Collections.Generic;
using In.ProjectEKA.HipLibrary.Patient.Model;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Link.Model
{
    public class GatewayAddContextsRequestRepresentation
    {
        public string AbhaAddress { get; }
        public IEnumerable<LinkConfirmationRepresentation> Patient { get; }
        
        public GatewayAddContextsRequestRepresentation(string abhaAddress, IEnumerable <LinkConfirmationRepresentation> patient)
        {
            AbhaAddress = abhaAddress;
            Patient = patient;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}