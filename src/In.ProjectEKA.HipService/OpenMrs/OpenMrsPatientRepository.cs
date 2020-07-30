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

        public OpenMrsPatientRepository(IPatientDal patientDal)
        {
            _patientDal = patientDal;
        }

        public Option<Patient> PatientWith(string referenceNumber)
        {
            throw new System.NotImplementedException();
        }

        public async Task<Option<Patient>> PatientWithAsync(string referenceNumber)
        {
            var result = await _patientDal.LoadPatientAsync(referenceNumber);

            return Option.Some(result.ToHipPatient(result.Name[0].Text));
        }
    }
}