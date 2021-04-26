using Hl7.Fhir.Model;
using Hl7.Fhir.Serialization;
using Hl7.Fhir.Utility;
using In.ProjectEKA.HipLibrary.Patient.Model;

namespace In.ProjectEKA.HipService.DataFlow
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Optional;
    using Serilog;

    public class CollectHipService : ICollectHipService
    {
        private readonly IOpenMrsPatientData openMrsPatientData;

        public CollectHipService(IOpenMrsPatientData openMrsPatientData)
        {
            this.openMrsPatientData = openMrsPatientData;
        }

        public async Task<Option<Entries>> CollectData(TraceableDataRequest dataRequest)
        {
            var bundles = new List<CareBundle>();
            var patientData = await FindPatientData(dataRequest);
            var careContextReferences = patientData.Keys.ToList();
            foreach (var careContextReference in careContextReferences)
            {
                foreach (var result in patientData.GetOrDefault(careContextReference))
                {
                    var bundle = new FhirJsonParser().Parse<Bundle>(result);
                    bundles.Add(new CareBundle(careContextReference, bundle));
                }
            }

            var entries = new Entries(bundles);
            return Option.Some(entries);
        }

        private async Task<Dictionary<string, List<string>>> FindPatientData(TraceableDataRequest request)
        {
            try
            {
                LogDataRequest(request);
                var toDate = request.DateRange.To;
                var fromDate = request.DateRange.From;
                var careContextsAndListOfDataFiles = new Dictionary<string, List<string>>();
                foreach (var grantedContext in request.CareContexts)
                {
                    var listOfDataFiles = new List<string>();
                    foreach (var hiType in request.HiType) 
                    {
                        var hiTypeStr = hiType.ToString().ToLower();
                        var result = await openMrsPatientData
                            .GetPatientData(request.PatientUuid, grantedContext.CareContextReference, toDate, fromDate,
                                hiTypeStr).ConfigureAwait(false);
                        if (result?.Any() == true)
                        {
                            result.ForEach(item => listOfDataFiles.Add(item));
                        }
                    }

                    careContextsAndListOfDataFiles.Add(grantedContext.CareContextReference, listOfDataFiles);
                }

                return careContextsAndListOfDataFiles;
            }
            catch (Exception e)
            {
                Log.Error("Error Occured while collecting data. {Error}", e);
            }

            return new Dictionary<string, List<string>>();
        }

        private static void LogDataRequest(TraceableDataRequest request)
        {
            var ccList = JsonConvert.SerializeObject(request.CareContexts);
            var requestedHiTypes = string.Join(", ", request.HiType.Select(hiType => hiType.ToString()));
            Log.Information("Data request received." +
                            $" transactionId:{request.TransactionId} , " +
                            $"CareContexts:{ccList}, " +
                            $"HiTypes:{requestedHiTypes}," +
                            $" From date:{request.DateRange.From}," +
                            $" To date:{request.DateRange.To}, " +
                            $"CallbackUrl:{request.DataPushUrl}, " +
                            $"PatientUuid:{request.PatientUuid}");
        }
    }
}