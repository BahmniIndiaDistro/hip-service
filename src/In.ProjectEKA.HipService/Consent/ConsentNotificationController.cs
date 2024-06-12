// ReSharper disable MemberCanBePrivate.Global

using In.ProjectEKA.HipService.Common;

namespace In.ProjectEKA.HipService.Consent
{
    using System;
    using System.Threading.Tasks;
    using Common.Model;
    using Gateway;
    using Gateway.Model;
    using Hangfire;
    using HipLibrary.Patient.Model;
    using Microsoft.AspNetCore.Mvc;
    using Model;
    using static Common.Constants;

    [ApiController]
    public class ConsentNotificationController : ControllerBase
    {
        private readonly IBackgroundJobClient backgroundJob;
        private readonly IConsentRepository consentRepository;
        private readonly GatewayClient gatewayClient;

        public ConsentNotificationController(
            IConsentRepository consentRepository,
            IBackgroundJobClient backgroundJob,
            GatewayClient gatewayClient)
        {
            this.consentRepository = consentRepository;
            this.backgroundJob = backgroundJob;
            this.gatewayClient = gatewayClient;
        }

        [HttpPost(PATH_CONSENTS_HIP)]
        public AcceptedResult ConsentNotification(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, 
            [FromBody] ConsentArtefactRepresentation consentArtefact)
        {
            backgroundJob.Enqueue(() => StoreConsent(consentArtefact, correlationId));
            return Accepted();
        }
        
        [NonAction]
        public async Task StoreConsent(ConsentArtefactRepresentation consentArtefact, String correlationId)
        {
            var notification = consentArtefact.Notification;

            if (notification.Status == ConsentStatus.GRANTED)
            {
                var consent = new Consent(notification.ConsentDetail.ConsentId,
                    notification.ConsentDetail,
                    notification.Signature,
                    notification.Status,
                    notification.ConsentId);
                await consentRepository.AddAsync(consent);
                var cmSuffix = consent.ConsentArtefact.ConsentManager.Id;
                var gatewayResponse = new GatewayConsentRepresentation(
                    Guid.NewGuid(),
                    DateTime.Now.ToUniversalTime().ToString(DateTimeFormat),
                    new ConsentUpdateResponse(ConsentUpdateStatus.OK.ToString(), notification.ConsentId),
                    null,
                    new Resp(consentArtefact.RequestId));
                await gatewayClient.SendDataToGateway(PATH_CONSENT_ON_NOTIFY, gatewayResponse, cmSuffix, correlationId);
            }
            else
            {
                await consentRepository.UpdateAsync(notification.ConsentId, notification.Status);
                if (notification.Status == ConsentStatus.REVOKED)
                {
                    var consent = await consentRepository.GetFor(notification.ConsentId);
                    var cmSuffix = consent.ConsentArtefact.ConsentManager.Id;
                    var gatewayResponse = new GatewayConsentRepresentation(
                        Guid.NewGuid(),
                        DateTime.Now.ToUniversalTime().ToString(DateTimeFormat),
                        new ConsentUpdateResponse(ConsentUpdateStatus.OK.ToString(), notification.ConsentId),
                        null,
                        new Resp(consentArtefact.RequestId));
                    await gatewayClient.SendDataToGateway(PATH_CONSENT_ON_NOTIFY, gatewayResponse, cmSuffix, correlationId);
                }
            }
        }
    }
}
