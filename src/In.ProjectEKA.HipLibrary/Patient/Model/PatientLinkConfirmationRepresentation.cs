using System.Collections.Generic;

namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    public class PatientLinkConfirmationRepresentation
    {
        public PatientLinkConfirmationRepresentation(IEnumerable<LinkConfirmationRepresentation> patient)
        {
            Patient = patient;
        }

        public IEnumerable<LinkConfirmationRepresentation> Patient { get; }
    }
}