using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.SmsNotification.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace In.ProjectEKA.HipService.SmsNotification
{
    using static Constants;

    [ApiController]
    
    public class SmsNotificationController : Controller
    {
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<SmsNotificationController> logger;
        private readonly BahmniConfiguration bahmniConfiguration;
        private readonly ISmsNotificationService _smsNotificationService;
        private readonly GatewayConfiguration gatewayConfiguration;
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;

        public SmsNotificationController(IGatewayClient gatewayClient,
            ILogger<SmsNotificationController> logger,
            ISmsNotificationService smsNotificationService,
            BahmniConfiguration bahmniConfiguration,
            GatewayConfiguration gatewayConfiguration,
            HttpClient httpClient,
            OpenMrsConfiguration openMrsConfiguration)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this._smsNotificationService = smsNotificationService;
            this.bahmniConfiguration = bahmniConfiguration;
            this.gatewayConfiguration = gatewayConfiguration;
            this.httpClient = httpClient;
            this.openMrsConfiguration = openMrsConfiguration;
        }


        [Route(PATH_HIP_SMS_NOTIFY)]
        public async Task<ActionResult> SendSMSNotification([FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] SmsNotifyRequest smsNotifyRequest)
        {
            var (gatewaySmsNotifyRequestRepresentation, error) =
                _smsNotificationService.SmsNotifyRequest(smsNotifyRequest, bahmniConfiguration);
            if (error != null)
                return StatusCode(StatusCodes.Status400BadRequest, error);
            var cmSuffix = gatewayConfiguration.CmSuffix;

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.SmsNotify,
                    "Request for sms Notify to gateway: {@GatewayResponse}",
                    gatewaySmsNotifyRequestRepresentation.dump(gatewaySmsNotifyRequestRepresentation));
                
                await gatewayClient.SendDataToGateway(PATH_SMS_NOTIFY, gatewaySmsNotifyRequestRepresentation,
                    cmSuffix, correlationId);
                return Accepted();
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.UserAuth, exception, "Error happened for sms Notify request");
            }
            return StatusCode(StatusCodes.Status504GatewayTimeout,
                new ErrorRepresentation(new Error(ErrorCode.GatewayTimedOut, "Gateway timed out")));


        }
        
        [Authorize]
        [HttpPost (PATH_SMS_ON_NOTIFY)]
        public AcceptedResult SmsNotifyStatus(OnSmsNotifyRequest request,
        [FromHeader(Name = REQUEST_ID), Required] string requestId,
        [FromHeader(Name = TIMESTAMP)] string timestamp)
        {
            logger.Log(LogLevel.Information,
                LogEvents.SmsNotify, "On Sms Notify request received." +
                                    $" RequestId:{requestId}, " +
                                    $" Timestamp:{timestamp}," +
                                    $" ResponseRequestId:{request.response.RequestId}, ");
            if (request.error != null)
            {
                logger.Log(LogLevel.Information,
                    LogEvents.SmsNotify, $" Error Code:{request.error.Code}," +
                                        $" Error Message:{request.error.Message}.");
            }
            else if (request.status != null)
            {
                logger.Log(LogLevel.Information,
                    LogEvents.SmsNotify, $" Status:{request.status},");
                
            }

            return Accepted();
        }
    }
}