using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using Hl7.Fhir.Serialization;

namespace In.ProjectEKA.HipService.OpenMrs
{
    using Hl7.Fhir.Model;
    public class FhirDiscoveryDataSource : IPatientDal
    {
        private readonly IOpenMrsClient openMrsClient;

        public FhirDiscoveryDataSource(IOpenMrsClient openMrsClient)
        {
            this.openMrsClient = openMrsClient;
        }

        public async Task<List<Patient>> LoadPatientsAsyncWithId(string healthId){
            var path = DiscoveryPathConstants.OnPatientPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (healthId != null)
            {
                query["identifier"] = healthId;
            }
            if (query.ToString() != ""){
                path = $"{path}?{query}";
            }
            var patients = new List<Patient>();
            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(content);
            bundle.Entry.ForEach(entry =>
            {
                if (entry.Resource.TryDeriveResourceType(out ResourceType outResourceType) && outResourceType.Equals(ResourceType.Patient))
                {
                    patients.Add((Patient) entry.Resource);
                }
            });
            return patients;
        }

        public async Task<List<Patient>> LoadPatientsAsync(string name, AdministrativeGender? gender, string yearOfBirth)
        {
            var path = DiscoveryPathConstants.OnPatientPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (!string.IsNullOrEmpty(name)) {
                query["name"]=name;
            }
            if (gender != null) {
                query["gender"]=gender.ToString().ToLower();
            }
            if (!string.IsNullOrEmpty(yearOfBirth)) {
                query["birthdate"]=yearOfBirth;
            }
            if (query.ToString() != ""){
                path = $"{path}?{query}";
            }

            var patients = new List<Patient>();
            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(content);
            bundle.Entry.ForEach(entry =>
            {
                if (entry.Resource.TryDeriveResourceType(out ResourceType outResourceType) && outResourceType.Equals(ResourceType.Patient))
                {
                    patients.Add((Patient) entry.Resource);
                }
            });
            return patients;
        }

        public async Task<Patient> LoadPatientAsync(string patientId) {
            var path = $"{DiscoveryPathConstants.OnPatientPath}/{patientId}";
            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();
            var patient = new FhirJsonParser().Parse<Patient>(content);
            return patient;
        }

        public async Task<Patient> LoadPatientAsyncWithIdentifier(string patientIdentifier)
        {
            var path = DiscoveryPathConstants.OnPatientPath;
            var query = HttpUtility.ParseQueryString(string.Empty);
            if (!string.IsNullOrEmpty(patientIdentifier)) {
                query["identifier"]=patientIdentifier;
            }
            if (query.ToString() != ""){
                path = $"{path}?{query}";
            }

            var response = await openMrsClient.GetAsync(path);
            var content = await response.Content.ReadAsStringAsync();
            var bundle = new FhirJsonParser().Parse<Bundle>(content);

            return (Patient) bundle.Entry[0].Resource;
        }
    }
}