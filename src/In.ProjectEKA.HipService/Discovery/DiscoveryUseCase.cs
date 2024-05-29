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
                if (patients.First().CareContexts.Count() > 0)
                {
                    return (patients.First(), null);
                }

                return (null,
                    new ErrorRepresentation(new Error(ErrorCode.NoCareContextFound, "Care Context Not Found")));
            }

            return (null,
                new ErrorRepresentation(new Error(ErrorCode.MultiplePatientsFound, "Multiple patients found")));
        }
    }
}