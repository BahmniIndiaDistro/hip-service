using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.Discovery.Mapper;

public static class PatientDiscoveryMapper
{
    public static List<PatientDiscoveryRepresentation> Map(PatientEnquiryRepresentation patientEnquiryRepresentation)
    {
        if (patientEnquiryRepresentation == null)
        {
            return null;
        }

        return patientEnquiryRepresentation.CareContexts
            .Where(cc => cc.HiTypes != null && cc.HiTypes.Any())
            .SelectMany(cc => cc.HiTypes.Select(hiType => new { HiType = hiType, CareContext = cc }))
            .GroupBy(x => x.HiType)
            .Select(group => new PatientDiscoveryRepresentation(patientEnquiryRepresentation.ReferenceNumber,
                patientEnquiryRepresentation.Display,
                group.Select(x => new CareContextRepresentation(x.CareContext.ReferenceNumber, x.CareContext.Display))
                    .ToList(),
                group.Key.ToString(),
                group.Count()))
            .ToList();
    }
}