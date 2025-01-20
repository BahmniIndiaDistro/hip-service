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
            AddContextsRequest addContextsRequest, string cmSuffix, Guid requestId)
        {
            var careContexts = addContextsRequest.CareContexts;
            var abhaAddress = addContextsRequest.ConsentManagerUserId;
            
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
                .Select(group => new LinkConfirmationRepresentation(addContextsRequest.ReferenceNumber,
                    addContextsRequest.Display,
                    group.Select(x => new CareContextRepresentation(x.CareContext.ReferenceNumber, x.CareContext.Display))
                        .ToList(),
                    group.Key.ToString(),
                    group.Count()))
                .ToList();
            var (_, exception1) = await linkPatientRepository.SaveRequestWith(
                    requestId.ToString(),
                    cmSuffix,
                    addContextsRequest.ConsentManagerUserId,
                    addContextsRequest.ReferenceNumber,
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
                Thread.Sleep(gatewayConfiguration.TimeOut + 8000);
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
            NotifyContextRequest notifyContextRequest)
        {
            var id = notifyContextRequest.PatientId;
            var patientReference = notifyContextRequest.PatientReference;
            var careContextReference = notifyContextRequest.CareContextReference;
            var hiTypes = notifyContextRequest.HiTypes;
            var hipId = notifyContextRequest.HipId;
            var patient = new NotificationPatientContext(id);
            var careContext = new NotificationCareContext(patientReference, careContextReference);
            var hip = new NotificationContextHip(hipId);
            var date = DateTime.Now.ToUniversalTime().ToString(DateTimeFormat);
            var timeStamp = DateTime.Now.ToUniversalTime().ToString(DateTimeFormat);
            var requestId = Guid.NewGuid();
            var notification = new NotificationContext(patient, careContext, hiTypes, date, hip);
            return new Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation>
                (new GatewayNotificationContextRepresentation(requestId, timeStamp, notification), null);
        }

        public async Task CallNotifyContext(NewContextRequest newContextRequest, CareContextRepresentation context)
        {
            var request =
                new HttpRequestMessage(HttpMethod.Get, hipConfiguration.Value.Url + PATH_NOTIFY_CONTEXTS);
            var notifyContext = new NotifyContextRequest(newContextRequest.HealthId,
                newContextRequest.PatientReferenceNumber,
                context.ReferenceNumber,
                Enum.GetValues(typeof(HiType))
                    .Cast<HiType>()
                    .Select(v => v.ToString())
                    .ToList(),
                bahmniConfiguration.Id
            );
            request.Content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(notifyContext),
                Encoding.UTF8, "application/json");

            await httpClient.SendAsync(request).ConfigureAwait(false);
        }

        public async Task CallAddContext(NewContextRequest newContextRequest)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, hipConfiguration.Value.Url + PATH_ADD_CONTEXTS);
            var addContextRequest = new AddContextsRequest(
                newContextRequest.PatientReferenceNumber,
                newContextRequest.CareContexts,
                newContextRequest.PatientName,
                newContextRequest.HealthId);

            request.Content = new StringContent(JsonConvert.SerializeObject(addContextRequest),
                Encoding.UTF8, "application/json");
            await httpClient.SendAsync(request).ConfigureAwait(false);
        }

        public bool IsLinkedContext(List<string> careContexts, string context)
        {
            return careContexts.Any(careContext => careContext.Equals(context));
        }
    }
}