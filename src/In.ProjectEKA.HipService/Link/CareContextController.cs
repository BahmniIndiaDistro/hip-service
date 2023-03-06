using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace In.ProjectEKA.HipService.Link
{
    using static Constants;

    [ApiController]
    public class CareContextController : Controller
    {
        private readonly GatewayConfiguration gatewayConfiguration;
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<CareContextController> logger;
        private readonly ICareContextService careContextService;
        private readonly ILinkPatientRepository linkPatientRepository;

        public CareContextController(IGatewayClient gatewayClient,
            ILogger<CareContextController> logger,
            GatewayConfiguration gatewayConfiguration,
            ICareContextService careContextService,
            ILinkPatientRepository linkPatientRepository
        )
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.gatewayConfiguration = gatewayConfiguration;
            this.careContextService = careContextService;
            this.linkPatientRepository = linkPatientRepository;
        }

        [Route(PATH_ADD_CONTEXTS)]
        public async Task<ActionResult> AddContexts(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] AddContextsRequest addContextsRequest)
        {
            await careContextService.SetAccessToken(addContextsRequest.ConsentManagerUserId);
            var cmSuffix = gatewayConfiguration.CmSuffix;
            var (gatewayAddContextsRequestRepresentation, error) =
               await careContextService.AddContextsResponse(addContextsRequest,cmSuffix);
            if (error != null)
                return StatusCode(StatusCodes.Status400BadRequest, error);
            Guid requestId = gatewayAddContextsRequestRepresentation.RequestId;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.AddContext,
                    "Request for add-context to gateway: {@GatewayResponse}",
                    gatewayAddContextsRequestRepresentation.dump(gatewayAddContextsRequestRepresentation));
                logger.Log(LogLevel.Information, LogEvents.AddContext, $"cmSuffix: {{cmSuffix}}," +
                                                                     $" correlationId: {{correlationId}}, " +
                                                                     $"requestId: {{requestId}}",
                    cmSuffix, correlationId, requestId);
                await gatewayClient.SendDataToGateway(PATH_ADD_PATIENT_CONTEXTS,
                    gatewayAddContextsRequestRepresentation,
                    cmSuffix, correlationId);
                return Accepted();
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.AddContext, exception, "Error happened for requestId: {RequestId} for" +
                                                                 " add-care context request", requestId);
            }

            return StatusCode(StatusCodes.Status504GatewayTimeout,
                new ErrorRepresentation(new Error(ErrorCode.GatewayTimedOut, "Gateway timed out")));
        }

        [Route(PATH_NOTIFY_CONTEXTS)]
        public async Task<ActionResult> NotificationContext(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromBody] NotifyContextRequest notifyContextRequest)
        {
            var (gatewayNotificationContextRepresentation, error) =
                careContextService.NotificationContextResponse(notifyContextRequest);
            if (error != null)
                return StatusCode(StatusCodes.Status400BadRequest, error);
            Guid requestId = gatewayNotificationContextRepresentation.requestId;
            var cmSuffix = gatewayConfiguration.CmSuffix;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.AddContext,
                    "Request for notification-contexts to gateway: {@GatewayResponse}",
                    gatewayNotificationContextRepresentation.dump(gatewayNotificationContextRepresentation));
                await gatewayClient.SendDataToGateway(PATH_NOTIFY_PATIENT_CONTEXTS,
                    gatewayNotificationContextRepresentation,
                    cmSuffix, correlationId);
                return Accepted();
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.AddContext, exception, "Error happened for requestId: {RequestId} for" +
                                                                 " notification-care context request", requestId);
            }

            return StatusCode(StatusCodes.Status504GatewayTimeout,
                new ErrorRepresentation(new Error(ErrorCode.GatewayTimedOut, "Gateway timed out")));
        }

        [HttpPost(PATH_ON_NOTIFY_CONTEXTS)]
        public AcceptedResult HipLinkOnNotifyContexts(HipLinkContextConfirmation confirmation)
        {
            Log.Information("Link on-notify context received." +
                            $" RequestId:{confirmation.RequestId}, " +
                            $" Timestamp:{confirmation.Timestamp}");
            if (confirmation.Error != null)
                Log.Information($" Error Code:{confirmation.Error.Code}," +
                                $" Error Message:{confirmation.Error.Message}");
            else if (confirmation.Acknowledgement != null)
                Log.Information($" Acknowledgment Status:{confirmation.Acknowledgement.Status}");
            Log.Information($" Resp RequestId:{confirmation.Resp.RequestId}");
            return Accepted();
        }

        [Route(PATH_NEW_CARECONTEXT)]
        public async Task<ActionResult> PassContext([FromBody] NewContextRequest newContextRequest)
        {
            var (careContexts, exception) =
                await linkPatientRepository.GetLinkedCareContextsOfPatient(newContextRequest.PatientReferenceNumber);
            foreach (var context in newContextRequest.CareContexts)
            {
                if (careContexts != null && careContextService.IsLinkedContext(careContexts, context.ReferenceNumber))
                {
                    await careContextService.CallNotifyContext(newContextRequest, context);
                }
                else
                {
                    await careContextService.CallAddContext(newContextRequest);
                }
            }
            return StatusCode(StatusCodes.Status200OK);
        }
    }
}