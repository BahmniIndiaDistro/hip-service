using System;
using System.Collections.Generic;
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

        public async Task<IEnumerable<CareContextRepresentation>> GetCareContexts(string patientUuid)
        {
            var path = DiscoveryPathConstants.CareContextPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (!string.IsNullOrEmpty(patientUuid))
            {
                query["patientUuid"] = patientUuid;
            }

            if (query.ToString() != "")
            {
                path = $"{path}?{query}";
            }

            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;
            var careContexts = new List<CareContextRepresentation>();

            for (var i = 0; i < root.GetArrayLength(); i++)
            {
                var careContextType = root[i].GetProperty("careContextType").ToString();
                var careContextName = root[i].GetProperty("careContextName").GetString();
                var careContextReferenceNumber = root[i].GetProperty("careContextReference").ToString();
                var hiTypes = ParseHiTypesOfCareContext(root[i].GetProperty("hiTypes"));
                if (careContextType.Equals("PROGRAM"))
                {
                    careContextName = careContextName + "(ID Number:" + careContextReferenceNumber + ")";
                    careContextReferenceNumber = "";
                }
                
                careContexts.Add(new CareContextRepresentation(careContextReferenceNumber,careContextName,
                    careContextType,hiTypes));
            }

            return careContexts;
        }
        
        private List<HiType> ParseHiTypesOfCareContext(JsonElement hiTypes)
        {
            var hiTypesList = new List<HiType>();
            for (var i = 0; i < hiTypes.GetArrayLength(); i++)
            {
                hiTypesList.Add((HiType)Enum.Parse(typeof(HiType),hiTypes[i].ToString(), true));
            }
            return hiTypesList;
        }
    }
}