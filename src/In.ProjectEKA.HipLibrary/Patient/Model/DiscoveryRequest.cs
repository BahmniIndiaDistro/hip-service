using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    using System;

    public class DiscoveryRequest
    {
        public PatientEnquiry Patient { get; }


        [Required, MaxLength(50)]
        public string TransactionId { get; }


        public DiscoveryRequest(PatientEnquiry patient, string transactionId)
        {
            Patient = patient;
            TransactionId = transactionId;
        }
    }
}