using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using In.ProjectEKA.HipLibrary.Patient;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.OpenMrs
{
    public class OpenMrsCareContextRepository : ICareContextRepository
    {
        private readonly IOpenMrsClient openMrsClient;
        public OpenMrsCareContextRepository(IOpenMrsClient openMrsClient)
        {
            this.openMrsClient = openMrsClient;
        }

        public async Task<IEnumerable<CareContextRepresentation>> GetCareContexts(string patientReferenceNumber)
        {
            var combinedCareContexts = new List<CareContextRepresentation>();
            var programCareContexts = await LoadProgramEnrollments(patientReferenceNumber);
            combinedCareContexts.AddRange(programCareContexts);

            var visitCareContexts = await LoadVisits(patientReferenceNumber);
            combinedCareContexts.AddRange(visitCareContexts);

            return combinedCareContexts;
        }

        public virtual async Task<List<CareContextRepresentation>> LoadProgramEnrollments(string uuid)
        {
            var path = DiscoveryPathConstants.OnProgramEnrollmentPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (!string.IsNullOrEmpty(uuid))
            {
                query["patient"] = uuid;
            }
            if (query.ToString() != "")
            {
                path = $"{path}/?{query}";
            }

            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();

            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;

            Logger.Log.Information("response from program enrollments: {0}", content);
/*
response from program enrollments: 
    {
        "results": [
            {
                "uuid":"14f5a670-a7f7-474c-89de-77aa107707ad",
                "display":"test program",
                "links": [
                    {
                        "rel":"self",
                        "uri":"http://bahmni-0.92.bahmni-covid19.in/openmrs/ws/rest/v1/bahmniprogramenrollment/14f5a670-a7f7-474c-89de-77aa107707ad"
                    }
                ]
            }
        ]
    }
*/
            var careContexts = new List<CareContextRepresentation>();
            var results = root.GetProperty("results");
            for (int i = 0; i < results.GetArrayLength(); i++)
            {
                // **PREVIOUS IMPLEMENTATION
                // var attributes = results[i].GetProperty("attributes");
                // var referenceNumber = attributes[0].GetProperty("value").GetString();

                // **NEW IMPLEMENTATION BASED ON RESPONSE FROM AWS BAHMNI INSTANCE
                var referenceNumber = results[i].GetProperty("uuid").GetString();

                var display = results[i].GetProperty("display").GetString();
                careContexts.Add(new CareContextRepresentation(referenceNumber, display));
            }

            return careContexts;
        }

        public virtual async Task<List<CareContextRepresentation>> LoadVisits(string uuid)
        {
            var path = DiscoveryPathConstants.OnVisitPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (!string.IsNullOrEmpty(uuid))
            {
                query["patient"] = uuid;
                query["v"] = "full";
            }
            if (query.ToString() != "")
            {
                path = $"{path}/?{query}";
            }

            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();

            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;

            var careContexts = new List<CareContextRepresentation>();
            var results = root.GetProperty("results");
            for (int i = 0; i < results.GetArrayLength(); i++)
            {
                var visitType = results[i].GetProperty("visitType");
                var display = visitType.GetProperty("display").GetString();
                careContexts.Add(new CareContextRepresentation(null, display));
            }

            List<CareContextRepresentation> uniqueCareContexts = careContexts
                .GroupBy(careContext => careContext.Display)
                .Select(visitType => visitType.First())
                .ToList();

            return uniqueCareContexts;
        }
    }
}