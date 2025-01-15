using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Discovery
{
    using System;
    using System.Linq;
    using HipLibrary.Patient.Model;

    public static class DiscoveryUseCase
    {
        public static ValueTuple<PatientEnquiryRepresentation, ErrorRepresentation> DiscoverPatient(
            IEnumerable<PatientEnquiryRepresentation> patients)
        {
            if (!patients.Any())
                return (null, new ErrorRepresentation(new Error(ErrorCode.NoPatientFound, "No patient found")));

            if (patients.Count() == 1)
            {
                var patient = patients.First();
                if (patient.CareContexts == null || !patient.CareContexts.Any())
                    return (null, new ErrorRepresentation(new Error(ErrorCode.CareContextNotFound, "No care context found")));
                return (patient, null);
            }

            return (null,
                new ErrorRepresentation(new Error(ErrorCode.MultiplePatientsFound, "Multiple patients found")));
        }
    }
}