using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient;
using In.ProjectEKA.HipService.OpenMrs.Mappings;
using Optional;

namespace In.ProjectEKA.HipService.OpenMrs
{
    using In.ProjectEKA.HipLibrary.Patient.Model;

    public class OpenMrsPatientRepository : IPatientRepository
    {
        private readonly IPatientDal _patientDal;
        private readonly ICareContextRepository _careContextRepository;
        private readonly IPhoneNumberRepository _phoneNumberRepository;
        private const int PHONE_NUMBER_LENGTH = 10;

        public OpenMrsPatientRepository(IPatientDal patientDal, ICareContextRepository careContextRepository,
            IPhoneNumberRepository phoneNumberRepository)
        {
            _patientDal = patientDal;
            _careContextRepository = careContextRepository;
            _phoneNumberRepository = phoneNumberRepository;
        }

        public async Task<Option<Patient>> PatientWithAsync(string patientIdentifier)
        {
            var fhirPatient = await _patientDal.LoadPatientAsyncWithIdentifier(patientIdentifier);
            var firstName = fhirPatient.Name[0].GivenElement.FirstOrDefault().ToString();
            var hipPatient = fhirPatient.ToHipPatient(firstName);
            var referenceNumber = hipPatient.Uuid;
            hipPatient.CareContexts = await _careContextRepository.GetCareContexts(referenceNumber);
            hipPatient.PhoneNumber = await _phoneNumberRepository.GetPhoneNumber(referenceNumber);

            return Option.Some(hipPatient);
        }

        public async Task<IQueryable<Patient>> PatientsWithVerifiedId(string healthId)
        {
            var result = new List<Patient>();
            var fhirPatient = await _patientDal.LoadPatientsAsyncWithId(healthId);
            if (fhirPatient.Capacity <= 0) return new List<Patient>().AsQueryable();
            var hipPatient = fhirPatient.First().ToHipPatient(fhirPatient.First().Name.ToString());
            result.Add(hipPatient);
            return result.ToList().AsQueryable();
        }

        public async Task<IQueryable<Patient>> PatientsWithDemographics(string name,
            AdministrativeGender? gender, string yearOfBirth, string phoneNumber)
        {
            var result = new List<Patient>();
            var fhirPatients = await _patientDal.LoadPatientsAsync(name, gender, yearOfBirth);
            foreach (var patient in fhirPatients)
            {
                if (!CheckIfPatientAlreadyHasAbhaIdentifier(patient.Identifier))
                {
                    var hipPatient = patient.ToHipPatient(name);
                    var referenceNumber = hipPatient.Uuid;
                    var bahmniPhoneNumber = _phoneNumberRepository.GetPhoneNumber(referenceNumber).Result;
                    if (bahmniPhoneNumber != null && phoneNumber[^PHONE_NUMBER_LENGTH..].Equals(bahmniPhoneNumber[^PHONE_NUMBER_LENGTH..]))
                    {
                        result.Add(hipPatient);
                    }
                }
            }
            return result.ToList().AsQueryable();
        }

        private Boolean CheckIfPatientAlreadyHasAbhaIdentifier(List<Hl7.Fhir.Model.Identifier> identifiers)
        {
            return identifiers.Any(identifier =>
                (identifier.Type.Text.Equals("ABHA Number") || identifier.Type.Text.Equals("ABHA Address"))
            );
        }
    }
}