using In.ProjectEKA.HipService.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.DataFlow.Model;
namespace In.ProjectEKA.HipService.DataFlow
{
    public class DataFlowClient
    {
        private readonly DataFlowNotificationClient dataFlowNotificationClient;
        private readonly GatewayConfiguration gatewayConfiguration;
        private HipService.Common.Model.BahmniConfiguration bahmniConfiguration;
        private readonly HttpClient httpClient;
        private readonly GatewayClient gatewayClient;
        private static readonly string MEDIA_APPLICATION_FHIR_JSON = "application/fhir+json";

        public DataFlowClient(HttpClient httpClient,
            DataFlowNotificationClient dataFlowNotificationClient,
            GatewayConfiguration gatewayConfiguration,
            HipService.Common.Model.BahmniConfiguration bahmniConfiguration,
            GatewayClient gatewayClient)
        {
            this.gatewayClient = gatewayClient;
            this.httpClient = httpClient;
            this.dataFlowNotificationClient = dataFlowNotificationClient;
            this.gatewayConfiguration = gatewayConfiguration;
            this.bahmniConfiguration = bahmniConfiguration;
        }

        public virtual async Task SendDataToHiu(TraceableDataRequest dataRequest,
            IEnumerable<Entry> data,
            KeyMaterial keyMaterial)
        {
            await PostTo(dataRequest.ConsentId,
                dataRequest.DataPushUrl,
                dataRequest.CareContexts,
                new DataResponse(dataRequest.TransactionId, data, keyMaterial),
                dataRequest.CmSuffix,
                dataRequest.CorrelationId).ConfigureAwait(false);
        }

        private async Task PostTo(string consentId,
            string dataPushUrl,
            IEnumerable<GrantedContext> careContexts,
            DataResponse dataResponse,
            string cmSuffix,
            string correlationId)
        {
            var grantedContexts = careContexts as GrantedContext[] ?? careContexts.ToArray();
            var hiStatus = HiStatus.DELIVERED;
            var sessionStatus = SessionStatus.TRANSFERRED;
            var message = "Successfully delivered health information";
            var requestId = Guid.NewGuid();
            // Extract visit UUID from first care context (format: "patientId:visitUuid")
            var visitUuid = grantedContexts.First() != null 
                ? bahmniConfiguration.ExtractVisitUuidFromReference(grantedContexts.First().CareContextReference)
                : null;
            string hipId = bahmniConfiguration.GetHfrIdByVisitUuid(visitUuid);
            try
            {
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

                // TODO: Need to handle non 2xx response also
                httpClient.DefaultRequestHeaders.Remove("Authorization");
                var token = await gatewayClient.Authenticate(correlationId).ConfigureAwait(false);
                if (token.HasValue)
                {
                    var reqDataPush = HttpRequestHelper.CreateHttpRequestWithContentType(HttpMethod.Post, dataPushUrl, dataResponse,
                        token.ValueOr(String.Empty), cmSuffix, correlationId,
                        MediaTypeNames.Application.Json, hipId, requestId.ToString(), null,
                        null, null, dataResponse.TransactionId);
                    await httpClient.SendAsync(reqDataPush).ConfigureAwait(false);
                }
                else
                {
                    hiStatus = HiStatus.ERRORED;
                    sessionStatus = SessionStatus.FAILED;
                    message = "Failed to deliver health information";
                    Log.Error($"Failed to authenticate while delivering health information to {dataPushUrl}");
                }
            }
            catch (Exception exception)
            {
                hiStatus = HiStatus.ERRORED;
                sessionStatus = SessionStatus.FAILED;
                message = "Failed to deliver health information";
                Log.Error(exception, exception.StackTrace);
            }

            try
            {
                var statusResponses = grantedContexts
                    .Select(grantedContext =>
                        new StatusResponse(grantedContext.CareContextReference, hiStatus,
                            message))
                    .ToList();
                var dataNotificationRequest = new DataNotificationRequest(dataResponse.TransactionId,
                    DateTime.Today.ToUniversalTime().ToString(Common.Constants.DateTimeFormat),
                    new Notifier(Type.HIP, gatewayConfiguration.ClientId),
                    new StatusNotification(sessionStatus, hipId, statusResponses),
                    consentId,
                    requestId);
                await GetDataNotificationRequest(dataNotificationRequest, cmSuffix, correlationId).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Error(ex, ex.Message);
            }
        }

        private async Task GetDataNotificationRequest(DataNotificationRequest dataNotificationRequest,
            string cmSuffix,
            string correlationId)
        {
            await dataFlowNotificationClient.NotifyGateway(cmSuffix, dataNotificationRequest, correlationId);
        }
    }
}
