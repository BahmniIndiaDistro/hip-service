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
                DateTime.Now.ToUniversalTime(),
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
            [FromBody] ShareProfileRequest shareProfileRequest)
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
                token = await _patientProfileService.SavePatient(shareProfileRequest);
            }

            var gatewayResponse = new ProfileShareConfirmation(
                Guid.NewGuid().ToString(),
                DateTime.Now.ToUniversalTime(),
                new ProfileShareAcknowledgement(status.ToString(),shareProfileRequest.Profile.PatientDemographics.HealthId,token.ToString()), error,
                new Resp(shareProfileRequest.RequestId));
            Task.Run(async () =>
            {
                await Task.Delay(500);
                await _gatewayClient.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                    gatewayResponse,
                    cmSuffix,
                    correlationId);
                if(error == null)
                    await _patientProfileService.linkToken(shareProfileRequest.Profile.PatientDemographics);
            });
            if (error == null)
            {
                return Accepted();
            }
            return BadRequest();
        }
        
        [Route(PATH_PROFILE_FETCH)]
        public async Task<ActionResult> GetDetails()
        {
            var patientQueueResult = await _patientProfileService.GetPatientQueue();
            return Accepted(patientQueueResult);
        }

        
    }
}
