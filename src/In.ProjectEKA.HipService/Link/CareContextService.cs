using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.UserAuth;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.Extensions.Options;
using Optional.Unsafe;

namespace In.ProjectEKA.HipService.Link
{
    using static Constants;

    public class CareContextService : ICareContextService
    {
        private readonly HttpClient httpClient;
        private readonly IUserAuthRepository userAuthRepository;
        private readonly IUserAuthService  userAuthService;
        private readonly BahmniConfiguration bahmniConfiguration;
        private readonly ILinkPatientRepository linkPatientRepository;
        private readonly LinkPatient linkPatient;
        private readonly IOptions<HipConfiguration> hipConfiguration;
        private readonly IGatewayClient gatewayClient;
        private readonly GatewayConfiguration gatewayConfiguration;        
        public CareContextService(HttpClient httpClient, IUserAuthRepository userAuthRepository,
            BahmniConfiguration bahmniConfiguration, ILinkPatientRepository linkPatientRepository, LinkPatient linkPatient, IOptions<HipConfiguration> hipConfiguration, IGatewayClient gatewayClient, GatewayConfiguration gatewayConfiguration,
            IUserAuthService userAuthService)
        {
            this.httpClient = httpClient;
            this.userAuthRepository = userAuthRepository;
            this.bahmniConfiguration = bahmniConfiguration;
            this.linkPatientRepository = linkPatientRepository;
            this.linkPatient = linkPatient;
            this.hipConfiguration = hipConfiguration;
            this.gatewayClient = gatewayClient;
            this.gatewayConfiguration = gatewayConfiguration;
            this.userAuthService = userAuthService;
        }

        public async Task<Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>> AddContextsResponse(
            NewContextRequest addContextsRequest, string cmSuffix, Guid requestId)
        {
            var careContexts = addContextsRequest.CareContexts;
            var abhaAddress = addContextsRequest.HealthId;
            var linkReferenceNumber = Guid.NewGuid().ToString();
            
            if (!await linkPatient.SaveInitiatedLinkRequest(requestId.ToString(), null, linkReferenceNumber)
                .ConfigureAwait(false))
                return new Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>
                    (null, new ErrorRepresentation(new Error(ErrorCode.DuplicateRequestId, ErrorMessage.DuplicateRequestId)));
            var careContextReferenceNumbers = addContextsRequest.CareContexts
                .Select(context => context.ReferenceNumber)
                .ToArray();
            var linkConfirmationRepresentations = careContexts
                .Where(cc => cc.HiTypes != null && cc.HiTypes.Any())
                .SelectMany(cc => cc.HiTypes.Select(hiType => new { HiType = hiType, CareContext = cc }))
                .GroupBy(x => x.HiType)
                .Select(group => new LinkConfirmationRepresentation(addContextsRequest.PatientReferenceNumber,
                    addContextsRequest.PatientName,
                    group.Select(x => new CareContextRepresentation(x.CareContext.ReferenceNumber, x.CareContext.Display))
                        .ToList(),
                    group.Key.ToString(),
                    group.Count()))
                .ToList();
            var (_, exception1) = await linkPatientRepository.SaveRequestWith(
                    linkReferenceNumber,
                    cmSuffix,
                    abhaAddress,
                    addContextsRequest.PatientReferenceNumber,
                    careContextReferenceNumbers)
                .ConfigureAwait(false);
            if (exception1 != null)
                return new Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>
                (null, new ErrorRepresentation(new Error(ErrorCode.ServerInternalError,
                    ErrorMessage.DatabaseStorageError)));
            return new Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>
                (new GatewayAddContextsRequestRepresentation(
                    abhaAddress,
                    linkConfirmationRepresentations), null);
        }
        
        public async Task SetAccessToken(string healthId, string hipId)
        {
            var demographics = (userAuthRepository.GetDemographics(healthId).Result).ValueOrDefault();
            if (demographics != null)
                UserAuthMap.UpdateHealthIdToPhoneNumber(demographics.PhoneNumber, healthId);
            var compositeKey = healthId + COMPOSITE_AUTH_KEY_SEPARATOR + hipId;
            if (UserAuthMap.HealthIdToAccessToken.ContainsKey(compositeKey))
            {
                var linkToken = UserAuthMap.HealthIdToAccessToken[compositeKey];
                var error = userAuthService.CheckAccessToken(linkToken);
                if (error == null)
                    return;
            }
            var (linkTokenFromDb,exception) = await userAuthRepository.GetAccessToken(healthId, hipId);
            if (linkTokenFromDb != null)
            {
                 var error = userAuthService.CheckAccessToken(linkTokenFromDb);
                 if (error == null)
                 {
                     UserAuthMap.HealthIdToAccessToken.Add(compositeKey, linkTokenFromDb);
                     return;
                 }
            }
            var requestId = Guid.NewGuid();
            if (demographics == null)
                return;
            UserAuthMap.RequestIdToHipId.Add(requestId.ToString(), hipId);
            var generateTokenPayload = new GenerateLinkTokenRequest(demographics.HealthId, demographics.Name,
                demographics.Gender, demographics.DateOfBirth.Split("-").First());
            
            await gatewayClient.SendDataToGateway(PATH_GENERATE_TOKEN, generateTokenPayload, gatewayConfiguration.CmSuffix,
                Guid.NewGuid().ToString(), hipId:hipId, requestId.ToString());
            var i = 0;
            do
            {
                await Task.Delay(gatewayConfiguration.TimeOut + 8000);
                if (UserAuthMap.RequestIdToErrorMessage.ContainsKey(requestId))
                {
                    var gatewayError = UserAuthMap.RequestIdToErrorMessage[requestId];
                    UserAuthMap.RequestIdToErrorMessage.Remove(requestId);
                    break;
                }

                if (UserAuthMap.RequestIdToAccessToken.ContainsKey(requestId))
                {
                    Log.Information(
                        "Response about to be send for requestId: {RequestId} and HealthId: {HealthId}",
                        requestId, demographics.HealthId
                    );
                    break;
                }
                i++;
            } while (i < gatewayConfiguration.Counter);
        }

        public async Task<Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation>> NotificationContextResponse(
            NewContextRequest notifyContextRequest, CareContextRepresentation context)
        {
            var id = notifyContextRequest.HealthId;
            var patientReference = notifyContextRequest.PatientReferenceNumber;
            var careContextReference = context.ReferenceNumber;
            var hiTypes = context.HiTypes.Select(hiType => hiType.ToString()).ToList();
            // Extract visit UUID from care context reference (format: "patientId:visitUuid")
            var visitUuid = bahmniConfiguration.ExtractVisitUuidFromReference(careContextReference);
            var hipId = bahmniConfiguration.GetHfrIdByVisitUuid(visitUuid);
            if (string.IsNullOrEmpty(hipId))
            {
                Log.Information($"PostTo: Attempting to set HFR ID for visit UUID: {visitUuid}");
                var hfrId = await bahmniConfiguration.SetHfrIdForVisitAsync(visitUuid).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(hfrId))
                {
                    hipId = hfrId;
                    Log.Information($"PostTo: Successfully set HFR ID {hfrId} for visit UUID {visitUuid}");
                }
                else
                {
                    hipId = bahmniConfiguration.GetDefaultHfrId();
                }
            }
            var patient = new NotificationPatientContext(id);
            var careContext = new NotificationCareContext(patientReference, careContextReference);
            var hip = new NotificationContextHip(hipId);
            var date = DateTime.Now.ToUniversalTime().ToString(DateTimeFormat);
            var notification = new NotificationContext(patient, careContext, hiTypes, date, hip);
            return new Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation>
                (new GatewayNotificationContextRepresentation(notification), null);
        }

        public async Task CallNotifyContext(NewContextRequest newContextRequest, CareContextRepresentation context)
        {
            var (gatewayNotificationContextRepresentation, error) =
                await NotificationContextResponse(newContextRequest, context).ConfigureAwait(false);
            if (error != null)
                Log.Error("Notify for Care Context failed with error: {@Error}", error);
            
            var cmSuffix = gatewayConfiguration.CmSuffix;
            // Extract visit UUID from care context reference
            var visitUuid = bahmniConfiguration.ExtractVisitUuidFromReference(context.ReferenceNumber);
            var hipId = bahmniConfiguration.GetHfrIdByVisitUuid(visitUuid);
            if (string.IsNullOrEmpty(hipId))
            {
                Log.Information($"PostTo: Attempting to set HFR ID for visit UUID: {visitUuid}");
                var hfrId = await bahmniConfiguration.SetHfrIdForVisitAsync(visitUuid).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(hfrId))
                {
                    hipId = hfrId;
                    Log.Information($"PostTo: Successfully set HFR ID {hfrId} for visit UUID {visitUuid}");
                }
                else
                {
                    hipId = bahmniConfiguration.GetDefaultHfrId();
                }
            }
            try
            {
                var compositeKey = newContextRequest.HealthId + COMPOSITE_AUTH_KEY_SEPARATOR + hipId;
                if (!UserAuthMap.HealthIdToAccessToken.ContainsKey(compositeKey))
                {
                    Log.Error("Unable to get link token for healthId: {healthId} and hipId: {hipId}",
                        newContextRequest.HealthId, hipId);
                    throw new Exception("Unable to get link token");
                }
                var linkToken = UserAuthMap.HealthIdToAccessToken[compositeKey];
                UserAuthMap.UpdateHealthIdToLatestVisitUuid(newContextRequest.HealthId, visitUuid);
                Log.Information(
                    "Request for notification-contexts to gateway: {@GatewayResponse}",
                    gatewayNotificationContextRepresentation.dump(gatewayNotificationContextRepresentation));
                await gatewayClient.SendDataToGateway(PATH_NOTIFY_PATIENT_CONTEXTS,
                    gatewayNotificationContextRepresentation,
                    cmSuffix, Guid.NewGuid().ToString(), hipId:hipId, linkToken:linkToken, requestId: Guid.NewGuid().ToString());
            }
            catch (Exception exception)
            {
                Log.Error("Error happened for notification-care context request", exception);
            }
        }

        public async Task CallAddContext(NewContextRequest newContextRequest)
        {
            var abhaAddress = newContextRequest.HealthId;
            // Extract visit UUID from first care context (if available)
            var visitUuid = newContextRequest.CareContexts?.First() != null 
                ? bahmniConfiguration.ExtractVisitUuidFromReference(newContextRequest.CareContexts.First().ReferenceNumber)
                : null;
            UserAuthMap.UpdateHealthIdToLatestVisitUuid(abhaAddress, visitUuid);
            string hipId = bahmniConfiguration.GetHfrIdByVisitUuid(visitUuid);
            if (string.IsNullOrEmpty(hipId))
            {
                Log.Information($"PostTo: Attempting to set HFR ID for visit UUID: {visitUuid}");
                var hfrId = await bahmniConfiguration.SetHfrIdForVisitAsync(visitUuid).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(hfrId))
            {
                    hipId = hfrId;
                    Log.Information($"PostTo: Successfully set HFR ID {hfrId} for visit UUID {visitUuid}");
                }
                else
                {
                    hipId = bahmniConfiguration.GetDefaultHfrId();
                }
            }
            await SetAccessToken(abhaAddress, hipId);
            var compositeKey = abhaAddress + COMPOSITE_AUTH_KEY_SEPARATOR + hipId;
            if (!UserAuthMap.HealthIdToAccessToken.ContainsKey(compositeKey))
            {
                Log.Error("Unable to get link token for healthId: {healthId} and hipId: {hipId}", abhaAddress, hipId);
                throw new Exception("Unable to get link token");
            }
            var linkToken = UserAuthMap.HealthIdToAccessToken[compositeKey];
            var cmSuffix = gatewayConfiguration.CmSuffix;
            var requestId = Guid.NewGuid();
            var (gatewayAddContextsRequestRepresentation, error) =
                await AddContextsResponse(newContextRequest, cmSuffix, requestId);
            if (error != null)
            {
                Log.Error("Linking Care Context failed with error: {@Error}", error);
                return;
            }
            try
            {
                Log.Information(
                    "Request for add-context to gateway: {@GatewayResponse}",
                    gatewayAddContextsRequestRepresentation.dump(gatewayAddContextsRequestRepresentation));
                await gatewayClient.SendDataToGateway(PATH_ADD_PATIENT_CONTEXTS,
                    gatewayAddContextsRequestRepresentation,
                    cmSuffix, Guid.NewGuid().ToString(), hipId:hipId, linkToken:linkToken, requestId: requestId.ToString());
            }
            catch (Exception exception)
            {
                Log.Error("Error happened for add-care context request", exception);
            }
        }

        public bool IsLinkedContext(List<string> careContexts, string context)
        {
            return careContexts.Any(careContext => careContext.Equals(context));
        }
    }
}