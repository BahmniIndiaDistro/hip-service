using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.UserAuth;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Optional.Unsafe;
using HiType = In.ProjectEKA.HipLibrary.Patient.Model.HiType;

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
            
            if (!await linkPatient.SaveInitiatedLinkRequest(requestId.ToString(), null, requestId.ToString())
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
                    requestId.ToString(),
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
                (new GatewayAddContextsRequestRepresentation( abhaAddress,linkConfirmationRepresentations), null);
        }
        
        public async Task SetAccessToken(string healthId)
        {
            if (UserAuthMap.HealthIdToAccessToken.ContainsKey(healthId))
            {
                var linkToken = UserAuthMap.HealthIdToAccessToken[healthId];
                var error = userAuthService.CheckAccessToken(linkToken);
                if (error == null)
                    return;
            }
            var (linkTokenFromDb,exception) = await userAuthRepository.GetAccessToken(healthId);
            if (linkTokenFromDb != null)
            {
                 var error = userAuthService.CheckAccessToken(linkTokenFromDb);
                 if (error == null)
                 {
                     UserAuthMap.HealthIdToAccessToken.Add(healthId, linkTokenFromDb);
                     return;
                 }
            }
            
            var demographics = (userAuthRepository.GetDemographics(healthId).Result).ValueOrDefault();
            var requestId = Guid.NewGuid();
            if (demographics == null)
                return;
            var generateTokenPayload = new GenerateLinkTokenRequest(demographics.HealthId, demographics.Name,
                demographics.Gender, demographics.DateOfBirth.Split("-").First());
            
            await gatewayClient.SendDataToGateway(PATH_GENERATE_TOKEN, generateTokenPayload, gatewayConfiguration.CmSuffix,
                Guid.NewGuid().ToString(), bahmniConfiguration.Id, requestId.ToString() );
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
                        "Response about to be send for requestId: {RequestId} with accessToken: {AccessToken}",
                        requestId, UserAuthMap.RequestIdToAccessToken[requestId]
                    );
                    break;
                }
                i++;
            } while (i < gatewayConfiguration.Counter);
        }

        public Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation> NotificationContextResponse(
            NewContextRequest notifyContextRequest, CareContextRepresentation context)
        {
            var id = notifyContextRequest.HealthId;
            var patientReference = notifyContextRequest.PatientReferenceNumber;
            var careContextReference = context.ReferenceNumber;
            var hiTypes = context.HiTypes.Select(hiType => hiType.ToString()).ToList();
            var hipId = bahmniConfiguration.Id;
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
                NotificationContextResponse(newContextRequest, context);
            if (error != null)
                Log.Error("Notify for Care Context failed with error: {@Error}", error);
            
            var cmSuffix = gatewayConfiguration.CmSuffix;
            try
            {
                Log.Information(
                    "Request for notification-contexts to gateway: {@GatewayResponse}",
                    gatewayNotificationContextRepresentation.dump(gatewayNotificationContextRepresentation));
                await gatewayClient.SendDataToGateway(PATH_NOTIFY_PATIENT_CONTEXTS,
                    gatewayNotificationContextRepresentation,
                    cmSuffix, Guid.NewGuid().ToString(), hipId:bahmniConfiguration.Id);
                
            }
            catch (Exception exception)
            {
                Log.Error("Error happened for notification-care context request", exception);
            }
        }

        public async Task CallAddContext(NewContextRequest newContextRequest)
        {
            var abhaAddress = newContextRequest.HealthId;
            await SetAccessToken(abhaAddress);
            if (!UserAuthMap.HealthIdToAccessToken.ContainsKey(abhaAddress))
            {
                Log.Error("Unable to get link token for healthId: {healthId}",
                    abhaAddress);
                throw new Exception("Unable to get link token");
            }
            var linkToken = UserAuthMap.HealthIdToAccessToken[abhaAddress];
            var cmSuffix = gatewayConfiguration.CmSuffix;
            var requestId = Guid.NewGuid();
            var (gatewayAddContextsRequestRepresentation, error) =
                await AddContextsResponse(newContextRequest,cmSuffix,requestId);
            if (error != null)
                Log.Error("Linking Care Context failed with error: {@Error}", error);
            try
            {
                Log.Information(
                    "Request for add-context to gateway: {@GatewayResponse}",
                    gatewayAddContextsRequestRepresentation.dump(gatewayAddContextsRequestRepresentation));
                await gatewayClient.SendDataToGateway(PATH_ADD_PATIENT_CONTEXTS,
                    gatewayAddContextsRequestRepresentation,
                    cmSuffix, null, linkToken:linkToken, requestId: requestId.ToString(), hipId:bahmniConfiguration.Id);
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