using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.Patient.Database;
using In.ProjectEKA.HipService.Patient.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Optional;
using Optional.Unsafe;
using Task = System.Threading.Tasks.Task;

namespace In.ProjectEKA.HipService.Patient
{
    using static Common.Constants;
    public class PatientProfileService : IPatientProfileService
    {
        private readonly OpenMrsConfiguration _openMrsConfiguration;
        private readonly PatientContext patientContext;
        private readonly HttpClient httpClient;
        private readonly IOptions<HipConfiguration> hipConfiguration;

        public PatientProfileService(OpenMrsConfiguration openMrsConfiguration, PatientContext patientContext, HttpClient httpClient, IOptions<HipConfiguration> hipConfiguration)
        {
            this._openMrsConfiguration = openMrsConfiguration;
            this.patientContext = patientContext;
            this.httpClient = httpClient;
            this.hipConfiguration = hipConfiguration;
        }

        public async Task<int> SavePatient(ShareProfileRequest shareProfileRequest, string requestId, string timestamp)
        {
            var hipCode = shareProfileRequest.Metadata.HipId;
            var patient = shareProfileRequest.Profile.Patient;
            var response = await Save(new PatientQueue(requestId, timestamp, patient, hipCode));
            if(response.HasValue)
                Log.Information("Patient saved to queue");
            return response.ValueOrDefault();
        }

        private async Task<Option<int>> Save(PatientQueue patientQueue)
        {
            try
            {
                await patientContext.PatientQueue.AddAsync(patientQueue).ConfigureAwait(false);
                await patientContext.SaveChangesAsync();
                return Option.Some(patientQueue.TokenNumber);
            }
            catch (Exception exception)
            {
                Log.Fatal(exception, exception.StackTrace);
                return Option.Some(patientQueue.TokenNumber);
            }
        }
        public bool IsValidRequest(ShareProfileRequest shareProfileRequest)
        {
            var profile = shareProfileRequest?.Profile;
            var demographics = profile?.Patient;
            return demographics is {AbhaAddress: { }, Name: { },Gender:{}} && Enum.IsDefined(typeof(Gender), demographics.Gender) && demographics.YearOfBirth != 0;
        }
        public async Task<List<PatientQueue>> GetPatientQueue()
        {
            try
            {
                var patientQueueRequest = patientContext.PatientQueue.ToList().FindAll(
                    patient => DateTime.Now.Subtract (DateTime.Parse(patient.DateTimeStamp)).TotalMinutes < _openMrsConfiguration.PatientQueueTimeLimit
                );

                return patientQueueRequest;
            }
            catch (Exception exception)
            {
                Log.Fatal(exception, exception.StackTrace);
                return new List<PatientQueue>();
            }
        }

  
    }
}