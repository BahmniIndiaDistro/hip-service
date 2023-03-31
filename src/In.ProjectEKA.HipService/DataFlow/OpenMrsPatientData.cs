using System.Threading.Tasks;
using System.Web;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.OpenMrs;
using Serilog;
using System.Text.Json;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.DataFlow
{
    public class OpenMrsPatientData : IOpenMrsPatientData
    {
        private readonly Dictionary<string, string> hiTypeToRootElement = new Dictionary<string, string>()
        {
            {HiType.Prescription.ToString().ToLower(), "prescriptions"},
            {HiType.DiagnosticReport.ToString().ToLower(), "diagnosticReports"},
            {HiType.OPConsultation.ToString().ToLower(), "opConsults"},
            {HiType.DischargeSummary.ToString().ToLower(), "dischargeSummary"},
            {HiType.ImmunizationRecord.ToString().ToLower(), "immunizationRecord"},
            {HiType.HealthDocumentRecord.ToString().ToLower(), "healthDocumentRecord"}
        };

        private readonly IOpenMrsClient openMrsClient;

        public OpenMrsPatientData(IOpenMrsClient openMrsClient)
        {
            this.openMrsClient = openMrsClient;
        }

        private static bool IsProgramCareContext(string careContextName)
        {
            string pattern = @"\(ID Number:(\d+)\)";
            return Regex.Match(careContextName, pattern).Success;
        }

        public async Task<List<string>> GetPatientData(string patientUuid, string careContextReference, string toDate,
            string fromDate, string hiType)
        {
            if (!hiTypeToRootElement.ContainsKey(hiType)) return new List<string>();
            if (!IsProgramCareContext(careContextReference))
                return await GetForVisits(hiType, patientUuid, careContextReference, toDate, fromDate);
            var programName = careContextReference
                .Substring(0, careContextReference.IndexOf("(", StringComparison.Ordinal))
                .Trim();
            var indexOfClosingBracket = careContextReference.IndexOf(")", StringComparison.Ordinal);
            var indexOfColon = careContextReference.IndexOf(":", StringComparison.Ordinal);
            var programId = careContextReference
                .Substring(indexOfColon + 1, indexOfClosingBracket - indexOfColon - 1)
                .Trim();
            return await GetForPrograms(hiType, patientUuid, programName, programId, toDate, fromDate);
        }

        private async Task<List<string>> GetForVisits(string hiType, string consentId, string grantedContext,
            string toDate,
            string fromDate)
        {
            var pathForVisit = $"{Constants.PATH_OPENMRS_HITYPE}{hiTypeToRootElement[hiType]}/visit/";
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (
                !string.IsNullOrEmpty(consentId) &&
                !string.IsNullOrEmpty(grantedContext) &&
                !string.IsNullOrEmpty(toDate) &&
                !string.IsNullOrEmpty(fromDate)
            )
            {
                var careContexReference = grantedContext.Split(":");
                query["patientId"] = consentId;
                query["visitUuid"] = careContexReference[1];
                query["fromDate"] = DateTime.Parse(fromDate).ToString("yyyy-MM-dd");
                query["toDate"] = DateTime.Parse(toDate).AddDays(1).ToString("yyyy-MM-dd");
            }

            if (query.ToString() != "")
            {
                pathForVisit = $"{pathForVisit}?{query}";
            }

            Log.Information("VISIT endpoint being called: " + pathForVisit);
            var response = await openMrsClient.GetAsync(pathForVisit);
            if (response == null) return new List<string>();
            var content = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;
            var entries = root.GetProperty(hiTypeToRootElement[hiType]);
            var listOfData = new List<string>();
            if (entries.GetArrayLength() > 0)
            {
                foreach (JsonElement jsonElement in entries.EnumerateArray())
                {
                    listOfData.Add(jsonElement.GetProperty("bundle").ToString());
                }
            }

            return listOfData;
        }

        private async Task<List<string>> GetForPrograms(string hiType, string consentId, string programName,
            string programId,
            string toDate,
            string fromDate)
        {
            var pathForProgram = $"{Constants.PATH_OPENMRS_HITYPE}{hiTypeToRootElement[hiType]}/program/";
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (
                !string.IsNullOrEmpty(consentId) &&
                !string.IsNullOrEmpty(programName) &&
                !string.IsNullOrEmpty(toDate) &&
                !string.IsNullOrEmpty(fromDate)
            )
            {
                query["patientId"] = consentId;
                query["programName"] = programName;
                query["programEnrollmentId"] = programId;
                query["fromDate"] = fromDate;
                query["toDate"] = toDate;
            }

            if (query.ToString() != "")
            {
                pathForProgram = $"{pathForProgram}?{query}";
            }

            Log.Information("PROGRAM endpoint being called: " + pathForProgram);
            var response = await openMrsClient.GetAsync(pathForProgram);
            if (response == null) return new List<string>();
            var content = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;
            var entries = root.GetProperty(hiTypeToRootElement[hiType]);
            var listOfData = new List<string>();
            if (entries.GetArrayLength() > 0)
            {
                foreach (JsonElement jsonElement in entries.EnumerateArray())
                {
                    listOfData.Add(jsonElement.GetProperty("bundle").ToString());
                }
            }

            return listOfData;
        }
    }
}