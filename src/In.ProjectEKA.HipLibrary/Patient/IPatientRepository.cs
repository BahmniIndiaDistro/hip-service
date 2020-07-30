namespace In.ProjectEKA.HipLibrary.Patient
{
    using System.Threading.Tasks;
    using Model;
    using Optional;

    public interface IPatientRepository
    {
        Option<Patient> PatientWith(string referenceNumber);

        Task<Option<Patient>> PatientWithAsync(string referenceNumber);
    }
}