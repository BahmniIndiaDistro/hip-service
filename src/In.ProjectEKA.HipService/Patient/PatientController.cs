using In.ProjectEKA.HipService.Common;
using Microsoft.AspNetCore.Authorization;

namespace In.ProjectEKA.HipService.Patient
{
    using System;
    using System.Threading.Tasks;
    using Gateway;
    using HipLibrary.Patient.Model;
    using Microsoft.AspNetCore.Mvc;
    using Model;
    using static Common.Constants;

    [ApiController]
    public class PatientController : ControllerBase
    {
        private readonly GatewayClient _gatewayClient;
        private readonly IPatientNotificationService _patientNotificationService;
        private readonly GatewayConfiguration _gatewayConfiguration;
        private readonly IPatientProfileService _patientProfileService;


        public PatientController(GatewayClient gatewayClient, IPatientNotificationService patientNotificationService,
            GatewayConfiguration gatewayConfiguration, IPatientProfileService patientProfileService)
        {
            _gatewayClient = gatewayClient;
            _patientNotificationService = patientNotificationService;
            _gatewayConfiguration = gatewayConfiguration;
            _patientProfileService = patientProfileService;
        }

        [Route(PATH_PATIENT_NOTIFY)]
        public async Task<AcceptedResult> NotifyHip([FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromBody] HipPatientStatusNotification hipPatientStatusNotification)
        {
            var cmSuffix = _gatewayConfiguration.CmSuffix;
            await _patientNotificationService.Perform(hipPatientStatusNotification);
            var gatewayResponse = new HipPatientNotifyConfirmation(
                Guid.NewGuid().ToString(),
                DateTime.Now.ToUniversalTime().ToString(DateTimeFormat),
                new PatientNotifyAcknowledgement(Status.SUCCESS.ToString()), null,
                new Resp(hipPatientStatusNotification.requestId.ToString()));
            await _gatewayClient.SendDataToGateway(PATH_PATIENT_ON_NOTIFY,
                gatewayResponse,
                cmSuffix,
                correlationId);
            return Accepted();
        }

        [Route(PATH_PROFILE_SHARE)]
        public async Task<ActionResult> StoreDetails([FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromBody] ShareProfileRequest shareProfileRequest, [FromHeader(Name = "request-id")] string requestId, [FromHeader(Name = "timestamp")] string timestamp)
        {
            var cmSuffix = _gatewayConfiguration.CmSuffix;
            var status = Status.SUCCESS; 
            Error error = null;
            if (!_patientProfileService.IsValidRequest(shareProfileRequest))
            {
                status = Status.FALIURE;
                error = new Error(ErrorCode.BadRequest, "Invalid Request Format");
            }

            int token = 0;
            if(error == null)
            {
                token = await _patientProfileService.SavePatient(shareProfileRequest,requestId, timestamp);
            }

            var gatewayResponse = new ProfileShareConfirmation(
                new ProfileShareAcknowledgement(status.ToString(),shareProfileRequest.Profile.Patient.AbhaAddress,new ProfileShareAckProfile(shareProfileRequest.Metadata.Context,token.ToString(),"1800")), error,
                new Resp(requestId));
            Task.Run(async () =>
            {
                await Task.Delay(500);
                await _gatewayClient.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                    gatewayResponse,
                    cmSuffix,
                    correlationId);
            });
            if (error == null)
            {
                return Accepted();
            }
            return BadRequest();
        }
        
        [Authorize(AuthenticationSchemes = BAHMNI_AUTH)]
        [Route(GET_PATIENT_QUEUE)]
        public async Task<ActionResult> GetDetails()
        {
            var patientQueueResult = await _patientProfileService.GetPatientQueue();
            return Accepted(patientQueueResult);
        }

        
    }
}
