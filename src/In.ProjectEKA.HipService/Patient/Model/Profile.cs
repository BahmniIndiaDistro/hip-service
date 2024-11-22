namespace In.ProjectEKA.HipService.Patient.Model
{
    public class Profile
    {
        public PatientDemographics Patient { get; }
        public Profile(PatientDemographics patient)
        {
            Patient = patient;
        }
    }
}