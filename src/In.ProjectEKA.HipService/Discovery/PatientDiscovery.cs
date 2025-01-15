using In.ProjectEKA.HipService.OpenMrs.Mappings;

namespace In.ProjectEKA.HipService.Discovery
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using HipLibrary.Matcher;
    using HipLibrary.Patient;
    using HipLibrary.Patient.Model;
    using In.ProjectEKA.HipService.Link.Model;
    using OpenMrs;
    using Link;
    using Microsoft.Extensions.Logging;
    using Logger;
    using Common;


    public class PatientDiscovery : IPatientDiscovery
    {
        private readonly IMatchingRepository matchingRepository;
        private readonly IDiscoveryRequestRepository discoveryRequestRepository;
        private readonly ILinkPatientRepository linkPatientRepository;
        private readonly IPatientRepository patientRepository;
        private readonly ICareContextRepository careContextRepository;
        private readonly ILogger<PatientDiscovery> logger;

        public PatientDiscovery(
            IMatchingRepository matchingRepository,
            IDiscoveryRequestRepository discoveryRequestRepository,
            ILinkPatientRepository linkPatientRepository,
            IPatientRepository patientRepository,
            ICareContextRepository careContextRepository,
            ILogger<PatientDiscovery> logger)
        {
            this.matchingRepository = matchingRepository;
            this.discoveryRequestRepository = discoveryRequestRepository;
            this.linkPatientRepository = linkPatientRepository;
            this.patientRepository = patientRepository;
            this.careContextRepository = careContextRepository;
            this.logger = logger;
        }

        private ValueTuple<DiscoveryRepresentation, ErrorRepresentation> GetError(string errorCode,
            string errorMessage)
        {
            return (null, new ErrorRepresentation(new Error(errorCode, errorMessage)));
        }

        public virtual async Task<ValueTuple<DiscoveryRepresentation, ErrorRepresentation>> PatientFor(
            DiscoveryRequest request)
        {
            if (await AlreadyExists(request.TransactionId))
            {
                logger.Log(LogLevel.Error, LogEvents.Discovery,
                    "Discovery Request already exists for {request.TransactionId}.");
                return (null,
                    new ErrorRepresentation(new Error(ErrorCode.DuplicateDiscoveryRequest,
                        "Discovery Request already exists")));
            }

            var (linkedAccounts, exception) = await linkPatientRepository.GetLinkedCareContexts(request.Patient.Id);

            if (exception != null)
            {
                logger.Log(LogLevel.Critical, LogEvents.Discovery, exception, "Failed to get care contexts");
                return (null,
                    new ErrorRepresentation(new Error(ErrorCode.FailedToGetLinkedCareContexts,
                        "Failed to get Linked Care Contexts")));
            }

            var linkedCareContexts = linkedAccounts.ToList();
            if (HasAny(linkedCareContexts))
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Discovery,
                    $"User has already linked care contexts: {request.TransactionId}");
                var patient =
                    await patientRepository.PatientWithAsync(linkedCareContexts.First().PatientReferenceNumber);
                return await patient
                    .Map(async patient =>
                    {
                        await discoveryRequestRepository.Add(new Model.DiscoveryRequest(request.TransactionId,
                            request.Patient.Id,
                            patient.Identifier));
                        return (new DiscoveryRepresentation(patient.ToPatientEnquiryRepresentation(
                                GetUnlinkedCareContexts(linkedCareContexts, patient))),
                            (ErrorRepresentation) null);
                    })
                    .ValueOr(Task.FromResult(GetError(ErrorCode.NoPatientFound, ErrorMessage.NoPatientFound)));
            }

            IQueryable<HipLibrary.Patient.Model.Patient> patients = null;
            IEnumerable<PatientEnquiryRepresentation> patientEnquiry = new List<PatientEnquiryRepresentation>();
            var healthIdRecords = false; 

            try
            {
                var phoneNumber = request.Patient?.VerifiedIdentifiers?
                    .FirstOrDefault(identifier => identifier.Type.Equals(IdentifierType.MOBILE))
                    ?.Value.ToString();
                var healthId = request.Patient?.Id ?? null;
                
                if (healthId != null) {
                    Log.Information("User name -> " + request.Patient?.Name + " healthId found -> " + healthId);
                } else {
                    Log.Information("No healthId found for this user " + request.Patient?.Name);
                }

                if (healthId != null) {
                    Log.Information("Executing records with healthId block for healthId " + healthId);
                    patients = await patientRepository.PatientsWithVerifiedId(healthId);
                    if (patients.Any()) {
                        healthIdRecords = true;
                        Log.Information("Patients found with healthId :-> Name->" + patients.First());
                        Log.Information("Phone Number" + patients.First().PhoneNumber);
                    }
                }

                if (!patients.Any())
                {
                    Log.Information("Executing records with demographics as below ~~> ");
                    Log.Information(request.Patient?.Name + " " + request.Patient?.Gender.ToOpenMrsGender() + " " + request.Patient?.YearOfBirth?.ToString() + " " + phoneNumber);
                    patients = await patientRepository.PatientsWithDemographics(request.Patient?.Name,
                        request.Patient?.Gender.ToOpenMrsGender(),
                        request.Patient?.YearOfBirth?.ToString(),
                        phoneNumber);
                    if (patients.Any())
                    {
                        healthIdRecords = false;
                        Log.Information("Patients found with demographics :-> Name->" + patients.First().Name);
                        Log.Information("Phone Number" + patients.First().PhoneNumber);
                    }
                }
                Log.Information("Result patient Count ~~~~~~~~~~~~~> " + patients.Count());
            }
            catch (OpenMrsConnectionException)
            {
                return GetError(ErrorCode.OpenMrsConnection, ErrorMessage.HipConnection);
            }

            try
            {
                foreach (var patient in patients)
                {
                    var careContexts = await careContextRepository.GetCareContexts(patient.Uuid);
                    foreach (var careContext in careContexts)
                    {
                        Log.Information("careContext Display ~~~~~~~~~~> " + careContext.Display);
                        Log.Information("careContext Type ~~~~~~~~~~> " + careContext.Type);
                        Log.Information("careContext Reference Number ~~~~~~~~~~> " + careContext.ReferenceNumber);
                        await linkPatientRepository.SaveCareContextMap(careContext);
                    }
                    patient.CareContexts = careContexts;
                }
            }

            catch (OpenMrsFormatException e)
            {
                logger.Log(LogLevel.Error,
                    LogEvents.Discovery, $"Could not get care contexts for transaction {request.TransactionId}.", e);
                return GetError(ErrorCode.CareContextConfiguration, ErrorMessage.HipConfiguration);
            }

            if (patients.Any()){
                patientEnquiry = healthIdRecords ? Filter.HealthIdRecords(patients, request)
                                                 : Filter.DemographicRecords(patients, request);   
            }

            var (patientEnquiryRepresentation, error) = DiscoveryUseCase.DiscoverPatient(patientEnquiry);
            if (error != null){
                Log.Information("We got error as ~~~~~~~~~~~~> " + error.Error.Message);
            }
            if (patientEnquiryRepresentation != null) {
                Log.Information("patientEnquiryRepresentation ~~~~~~~> " + patientEnquiryRepresentation);   
            }
            if (patientEnquiryRepresentation == null) {
                Log.Information($"No matching unique patient found for transaction {request.TransactionId}.", error);
                return (null, error);
            }

            await discoveryRequestRepository.Add(new Model.DiscoveryRequest(request.TransactionId,
                request.Patient.Id, patientEnquiryRepresentation.ReferenceNumber));
            return (new DiscoveryRepresentation(patientEnquiryRepresentation), null);
        }

        private async Task<bool> AlreadyExists(string transactionId)
        {
            return await discoveryRequestRepository.RequestExistsFor(transactionId);
        }

        private static bool HasAny(IEnumerable<LinkedAccounts> linkedAccounts)
        {
            return linkedAccounts.Any(account => true);
        }

        private static IEnumerable<CareContextRepresentation> GetUnlinkedCareContexts(
            IEnumerable<LinkedAccounts> linkedAccounts,
            HipLibrary.Patient.Model.Patient patient)
        {
            var allLinkedCareContexts = linkedAccounts
                .SelectMany(account => account.CareContexts)
                .ToList();

            return patient.CareContexts
                .Where(careContext =>
                    allLinkedCareContexts.Find(linkedCareContext =>
                        linkedCareContext == careContext.ReferenceNumber) == null);
        }
    }
}