using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.UserAuth;
using In.ProjectEKA.HipService.UserAuth.Model;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace In.ProjectEKA.HipService.Link
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Transactions;
    using Common;
    using Discovery;
    using HipLibrary.Patient;
    using HipLibrary.Patient.Model;
    using Logger;
    using Microsoft.Extensions.Options;
    using Model;
    using static In.ProjectEKA.HipService.Discovery.DiscoveryReqMap;
    
    public class LinkPatient
    {
        private readonly IDiscoveryRequestRepository discoveryRequestRepository;
        private readonly ILinkPatientRepository linkPatientRepository;
        private readonly IOptions<OtpServiceConfiguration> otpService;
        private readonly IPatientRepository patientRepository;
        private readonly IPatientVerification patientVerification;
        private readonly ReferenceNumberGenerator referenceNumberGenerator;
        private readonly IOpenMrsClient openMrsClient;
        private readonly IUserAuthService userAuthService;

        public LinkPatient(
            ILinkPatientRepository linkPatientRepository,
            IPatientRepository patientRepository,
            IPatientVerification patientVerification,
            ReferenceNumberGenerator referenceNumberGenerator,
            IDiscoveryRequestRepository discoveryRequestRepository,
            IOptions<OtpServiceConfiguration> otpService,
            IOpenMrsClient openMrsClient, IUserAuthService userAuthService)
        {
            this.linkPatientRepository = linkPatientRepository;
            this.patientRepository = patientRepository;
            this.patientVerification = patientVerification;
            this.referenceNumberGenerator = referenceNumberGenerator;
            this.discoveryRequestRepository = discoveryRequestRepository;
            this.otpService = otpService;
            this.openMrsClient = openMrsClient;
            this.userAuthService = userAuthService;
        }

        public virtual async Task<ValueTuple<PatientLinkEnquiryRepresentation, ErrorRepresentation>> LinkPatients(
            PatientLinkEnquiry request)
        {
            var (patient, error) = await PatientAndCareContextValidation(request);
            if (error != null)
            {
                Log.Error(error.Error.Message);
                return (null, error);
            }

            var linkRefNumber = referenceNumberGenerator.NewGuid();
            using (var scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
            {
                if (!await SaveInitiatedLinkRequest(request.RequestId, request.TransactionId, linkRefNumber)
                    .ConfigureAwait(false))
                    return (null,
                        new ErrorRepresentation(new Error(ErrorCode.DuplicateRequestId, ErrorMessage.DuplicateRequestId))
                        );

                var careContextReferenceNumbers = request.Patient.CareContexts
                    .Select(context => context.ReferenceNumber)
                    .ToArray();
                var (_, exception) = await linkPatientRepository.SaveRequestWith(
                    linkRefNumber,
                    request.Patient.ConsentManagerId,
                    request.Patient.ConsentManagerUserId,
                    request.Patient.ReferenceNumber,
                    careContextReferenceNumbers)
                    .ConfigureAwait(false);
                if (exception != null)
                    return (null,
                        new ErrorRepresentation(new Error(ErrorCode.ServerInternalError,
                            ErrorMessage.DatabaseStorageError)));

                var session = new Session(
                    linkRefNumber,
                    new Communication(CommunicationMode.MOBILE, patient.PhoneNumber),
                    new OtpGenerationDetail(otpService.Value.SenderSystemName,
                        OtpAction.LINK_PATIENT_CARECONTEXT.ToString()));
                var otpGeneration = await patientVerification.SendTokenFor(session);
                if (otpGeneration != null)
                    return (null,
                        new ErrorRepresentation(new Error(ErrorCode.OtpGenerationFailed, otpGeneration.Message)));

                await discoveryRequestRepository.Delete(request.TransactionId, request.Patient.ConsentManagerUserId)
                    .ConfigureAwait(false);

                scope.Complete();
            }

            var time = new TimeSpan(0, 0, otpService.Value.OffsetInMinutes, 0);
            var expiry = DateTime.Now.Add(time).ToUniversalTime().ToString(Constants.DateTimeFormat);
            var meta = new LinkReferenceMeta(nameof(CommunicationMode.MOBILE), patient.PhoneNumber, expiry);
            var patientLinkReferenceResponse = new PatientLinkEnquiryRepresentation(
                new LinkEnquiryRepresentation(linkRefNumber, "MEDIATED", meta));
            return (patientLinkReferenceResponse, null);
        }

        private async Task<ValueTuple<HipLibrary.Patient.Model.Patient, ErrorRepresentation>> PatientAndCareContextValidation(
            PatientLinkEnquiry request)
        {
            var patient = await patientRepository.PatientWithAsync(request.Patient.ReferenceNumber);
            return patient.Map(patient =>
                    {
                        var programs = request.Patient.CareContexts
                            .Where(careContext =>
                                patient.CareContexts.Any(c => c.ReferenceNumber == careContext.ReferenceNumber))
                            .Select(context => new CareContextRepresentation(context.ReferenceNumber,
                                patient.CareContexts.First(info => info.ReferenceNumber == context.ReferenceNumber)
                                    .Display)).ToList();
                        if (programs.Count != request.Patient.CareContexts.Count())
                            return (null, new ErrorRepresentation(new Error(ErrorCode.CareContextNotFound,
                                ErrorMessage.CareContextNotFound)));

                        return (patient, (ErrorRepresentation) null);
                    })
                .ValueOr((null,
                    new ErrorRepresentation(new Error(ErrorCode.NoPatientFound, ErrorMessage.NoPatientFound))));
        }

        public virtual async Task<ValueTuple<PatientLinkConfirmationRepresentation, string, ErrorRepresentation>>
            VerifyAndLinkCareContext(
            LinkConfirmationRequest request)
        {
            var (linkEnquires, exception) =
                await linkPatientRepository.GetPatientFor(request.LinkReferenceNumber);
            var cmId = "";
            if (exception != null)
                return (null,cmId,
                    new ErrorRepresentation(new Error(ErrorCode.NoLinkRequestFound, ErrorMessage.NoLinkRequestFound)));
            cmId = linkEnquires.ConsentManagerId;

            var errorResponse = await patientVerification.Verify(request.LinkReferenceNumber, request.Token);
            if (errorResponse != null)
                return (null,cmId, new ErrorRepresentation(errorResponse.toError()));

            var patient = await patientRepository.PatientWithAsync(linkEnquires.PatientReferenceNumber);
            return await patient.Map( async patient =>
                {
                    var savedLinkRequests = await linkPatientRepository.Get(request.LinkReferenceNumber);
                    savedLinkRequests.MatchSome(linkRequests =>
                    {
                        foreach (var linkRequest in linkRequests)
                        {
                            linkRequest.Status = true;
                            linkPatientRepository.Update(linkRequest);
                        }
                    });

                    var representations = linkEnquires.CareContexts
                        .Where(careContext =>
                            patient.CareContexts.Any(info => info.ReferenceNumber == careContext.CareContextName))
                        .Select(context => new CareContextRepresentation(context.CareContextName,
                            patient.CareContexts.First(info => info.ReferenceNumber == context.CareContextName)
                                .Display));
                    var patientLinkResponse = new PatientLinkConfirmationRepresentation(
                        new LinkConfirmationRepresentation(
                            linkEnquires.PatientReferenceNumber,
                            $"{patient.Name}",
                            representations));
                    var resp = await SaveLinkedAccounts(linkEnquires, patient.Uuid);
                    if (resp)
                    {
                        LinkAbhaIdentifier(patient.Uuid, linkEnquires.ConsentManagerUserId);
                        return (patientLinkResponse, cmId, (ErrorRepresentation) null);
                    } 
                    return (null,cmId,
                            new ErrorRepresentation(new Error(ErrorCode.NoPatientFound,
                                ErrorMessage.NoPatientFound)));
                }).ValueOr(
                    Task.FromResult<ValueTuple<PatientLinkConfirmationRepresentation, string, ErrorRepresentation>>(
                        (null, cmId,new ErrorRepresentation(new Error(ErrorCode.CareContextNotFound,
                            ErrorMessage.CareContextNotFound)))));
        }

        private async Task<bool> SaveLinkedAccounts(LinkEnquires linkEnquires,string patientUuid)
        {
            var linkedAccount = await linkPatientRepository.Save(
                linkEnquires.ConsentManagerUserId,
                linkEnquires.PatientReferenceNumber,
                linkEnquires.LinkReferenceNumber,
                linkEnquires.CareContexts.Select(context => context.CareContextName).ToList(),
                (patientUuid!=null?Guid.Parse(patientUuid): Guid.Empty)
                )
                .ConfigureAwait(false);
            
            return linkedAccount.HasValue;
            
        }
        
        private async void LinkAbhaIdentifier(string patientUuid, string abhaAddress)
        {
            var patient = PatientInfoMap[abhaAddress];
            var abhaNumberIdentifier =  patient?.VerifiedIdentifiers.FirstOrDefault(id => id.Type == IdentifierType.NDHM_HEALTH_NUMBER);
            var json = JsonConvert.SerializeObject(new PatientAbhaIdentifier(abhaNumberIdentifier?.Value, abhaAddress), new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                ContractResolver = new DefaultContractResolver
                {
                    NamingStrategy = new CamelCaseNamingStrategy()
                }
            });
            var resp = await openMrsClient.PostAsync(
                    $"{Constants.PATH_OPENMRS_UPDATE_IDENTIFIER}/{patientUuid}",
                    json
                )
                .ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                var ndhmDemographics = new NdhmDemographics(abhaAddress, patient.Name, patient.Gender.ToString(), patient.YearOfBirth.ToString(), patient.VerifiedIdentifiers.FirstOrDefault(id => id.Type == IdentifierType.MOBILE)?.Value);
                await userAuthService.Dump(ndhmDemographics);
            }
            else
            {
                Log.Error("Errored in linking the abha identifier to the patient");
            }
        }

        public async Task<bool> SaveInitiatedLinkRequest(string requestId, string transactionId,
            string linkReferenceNumber)
        {
            var savedLinkRequest = await linkPatientRepository.Save(requestId, transactionId, linkReferenceNumber)
                .ConfigureAwait(false);
            return savedLinkRequest.HasValue;
        }
        public async Task<ErrorRepresentation> VerifyAndLinkCareContexts(String requestId)
        {
            var (linkEnquires, exception) =
                await linkPatientRepository.GetPatientFor(requestId);
            var cmId = "";
            if (exception != null)
                return new ErrorRepresentation(new Error(ErrorCode.NoLinkRequestFound, ErrorMessage.NoLinkRequestFound));
            cmId = linkEnquires.ConsentManagerId;
            var patient = await patientRepository.PatientWithAsync(linkEnquires.PatientReferenceNumber);
            return await patient.Map( async patient =>
                {
                    var savedLinkRequests = await linkPatientRepository.Get(requestId);
                    savedLinkRequests.MatchSome(linkRequests =>
                    {
                        foreach (var linkRequest in linkRequests)
                        {
                            linkRequest.Status = true;
                            linkPatientRepository.Update(linkRequest);
                        }
                    });
                    return await SaveLinkedAccounts(linkEnquires,patient.Uuid)
                        ? (ErrorRepresentation) null
                        : new ErrorRepresentation(new Error(ErrorCode.NoPatientFound,
                                ErrorMessage.NoPatientFound));
                }).ValueOr(
                Task.FromResult<ErrorRepresentation>(new ErrorRepresentation(new Error(ErrorCode.CareContextNotFound,
                        ErrorMessage.CareContextNotFound))));
        }
    }
}