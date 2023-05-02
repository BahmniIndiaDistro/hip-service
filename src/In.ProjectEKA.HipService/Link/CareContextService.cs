using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Link.Model;
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
        private readonly BahmniConfiguration bahmniConfiguration;
        private readonly ILinkPatientRepository linkPatientRepository;
        private readonly LinkPatient linkPatient;
        private readonly IOptions<HipConfiguration> hipConfiguration;
        
        public CareContextService(HttpClient httpClient, IUserAuthRepository userAuthRepository,
            BahmniConfiguration bahmniConfiguration, ILinkPatientRepository linkPatientRepository, LinkPatient linkPatient, IOptions<HipConfiguration> hipConfiguration)
        {
            this.httpClient = httpClient;
            this.userAuthRepository = userAuthRepository;
            this.bahmniConfiguration = bahmniConfiguration;
            this.linkPatientRepository = linkPatientRepository;
            this.linkPatient = linkPatient;
            this.hipConfiguration = hipConfiguration;
        }

        public async Task<Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>> AddContextsResponse(
            AddContextsRequest addContextsRequest, string cmSuffix)
        {
            var accessToken = UserAuthMap.HealthIdToAccessToken[addContextsRequest.ConsentManagerUserId];
            var referenceNumber = addContextsRequest.ReferenceNumber;
            var careContexts = addContextsRequest.CareContexts;
            var display = addContextsRequest.Display;
            var patient = new AddCareContextsPatient(referenceNumber, display, careContexts);
            var link = new AddCareContextsLink(accessToken, patient);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            if (!await linkPatient.SaveInitiatedLinkRequest(requestId.ToString(), null, requestId.ToString())
                .ConfigureAwait(false))
                return new Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>
                    (null, new ErrorRepresentation(new Error(ErrorCode.DuplicateRequestId, ErrorMessage.DuplicateRequestId)));
            var careContextReferenceNumbers = addContextsRequest.CareContexts
                .Select(context => context.ReferenceNumber)
                .ToArray();
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
                (new GatewayAddContextsRequestRepresentation(requestId, timeStamp, link), null);
        }
        
        public async Task SetAccessToken(string healthId)
        {
            var demographics = (userAuthRepository.GetDemographics(healthId).Result).ValueOrDefault();
            var request = new HttpRequestMessage(HttpMethod.Post,  hipConfiguration.Value.Url + PATH_DEMOGRAPHICS);
            request.Content = new StringContent(JsonConvert.SerializeObject(demographics), Encoding.UTF8,
                "application/json");
            await httpClient.SendAsync(request).ConfigureAwait(false);
            if (!UserAuthMap.HealthIdToAccessToken.TryGetValue(healthId, out _))
            {
                var (accessToken, error) = await userAuthRepository.GetAccessToken(healthId);
                UserAuthMap.HealthIdToAccessToken.Add(healthId, accessToken);
            }
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
            var date = DateTime.Now.ToUniversalTime();
            var timeStamp = DateTime.Now.ToUniversalTime();
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