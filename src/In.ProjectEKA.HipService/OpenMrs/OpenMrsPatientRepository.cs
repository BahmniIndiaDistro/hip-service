using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.OpenMrs.Mappings;
using Optional;

namespace In.ProjectEKA.HipService.OpenMrs
{
    public class OpenMrsPatientRepository : IPatientRepository
    {
        private readonly IPatientDal _patientDal;
        private readonly ICareContextRepository _careContextRepository;

        public OpenMrsPatientRepository(IPatientDal patientDal, ICareContextRepository careContextRepository)
        {
            _patientDal = patientDal;
            _careContextRepository = careContextRepository;
        }

        public Option<Patient> PatientWith(string referenceNumber)
        {
            throw new System.NotImplementedException();
        }

        public async Task<Option<Patient>> PatientWithAsync(string referenceNumber)
        {
            var fhirPatient = await _patientDal.LoadPatientAsync(referenceNumber);
            var hipPatient = fhirPatient.ToHipPatient(fhirPatient.Name[0].Text);
            hipPatient.CareContexts = await _careContextRepository.GetCareContexts(referenceNumber);

            return Option.Some(hipPatient);
        }
    }
}