using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using In.ProjectEKA.HipService.Patient.Model;

namespace In.ProjectEKA.HipService.Link
{
    using System;
    using System.Threading.Tasks;
    using Discovery;
    using Gateway;
    using Gateway.Model;
    using Hangfire;
    using HipLibrary.Patient.Model;
    using Logger;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.ModelBinding;
    using static Common.Constants;
    using Model;

    [Authorize]
    [ApiController]
    [Consumes("application/json")]
    [Produces("application/json")]
    public class LinkController : ControllerBase
    {
        private readonly IDiscoveryRequestRepository discoveryRequestRepository;
        private readonly IBackgroundJobClient backgroundJob;
        private readonly LinkPatient linkPatient;
        private readonly GatewayClient gatewayClient;

        public LinkController(
            IDiscoveryRequestRepository discoveryRequestRepository,
            IBackgroundJobClient backgroundJob,
            LinkPatient linkPatient, GatewayClient gatewayClient)
        {
            this.discoveryRequestRepository = discoveryRequestRepository;
            this.backgroundJob = backgroundJob;
            this.linkPatient = linkPatient;
            this.gatewayClient = gatewayClient;
        }
        [HttpPost(PATH_LINKS_LINK_INIT)]
        [ProducesResponseType(StatusCodes.Status202Accepted)]
        public AcceptedResult LinkFor(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromHeader(Name = REQUEST_ID), Required] string requestId,
            [FromHeader(Name = TIMESTAMP)] string timestamp,
            [FromBody] LinkReferenceRequest request)
        {
            backgroundJob.Enqueue(() => LinkPatient(request, correlationId, requestId));
            return Accepted();
        }

        /// <summary>
        /// Link patient's care contexts
        /// </summary>
        /// <remarks>
        /// Links care contexts associated with only one patient
        ///
        /// 1. Validate account reference number and care context reference number
        /// 2. Validate transactionId in the request with discovery request entry to check whether there was a discovery and were these care contexts discovered or not for a given patient
        /// 3. Before linking, HIP needs to authenticate the request with the patient(Ex: OTP verification)
        /// 4. Communicate the mode of authentication of a successful request with Consent Manager
        /// </remarks>
        /// <response code="202">Request accepted</response>
        [HttpPost(PATH_LINKS_LINK_CONFIRM)]
        [ProducesResponseType(StatusCodes.Status202Accepted)]
        public AcceptedResult LinkPatientFor(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromHeader(Name = REQUEST_ID), Required] string requestId,
            [FromHeader(Name = TIMESTAMP)] string timestamp,
            [FromBody] LinkPatientRequest request)
        {
            backgroundJob.Enqueue(() => LinkPatientCareContextFor(request, correlationId, requestId));
            return Accepted();
        }

        [NonAction]
        public async Task LinkPatient(LinkReferenceRequest request, string correlationId, string requestId)
        {
            var cmUserId = request.AbhaAddress;
            var cmSuffix = cmUserId.Substring(cmUserId.LastIndexOf("@", StringComparison.Ordinal) + 1);
            var patientReferenceNumber = request.Patient?.ToList()[0].ReferenceNumber;
            var careContexts = request.Patient.SelectMany(record => record.CareContexts)
                .DistinctBy(c => c.ReferenceNumber)
                .ToList();
            var patient = new LinkEnquiry(
                cmSuffix,
                cmUserId,
                patientReferenceNumber,
                careContexts);
            try
            {
                var doesRequestExists = await discoveryRequestRepository.RequestExistsFor(
                    request.TransactionId,
                    request.AbhaAddress,
                    patientReferenceNumber);

                ErrorRepresentation errorRepresentation = null;
                if (!doesRequestExists)
                {
                    errorRepresentation = new ErrorRepresentation(
                        new Error(ErrorCode.DiscoveryRequestNotFound, ErrorMessage.DiscoveryRequestNotFound));
                }

                var patientReferenceRequest =
                    new PatientLinkEnquiry(request.TransactionId, requestId, patient);
                var patientLinkEnquiryRepresentation = new PatientLinkEnquiryRepresentation();

                var (linkReferenceResponse, error) = errorRepresentation != null
                    ? (patientLinkEnquiryRepresentation, errorRepresentation)
                    : await linkPatient.LinkPatients(patientReferenceRequest);
                var linkedPatientRepresentation = new LinkEnquiryRepresentation();
                if (linkReferenceResponse != null)
                {
                    linkedPatientRepresentation = linkReferenceResponse.Link;
                }
                if (error != null)
                    Log.Error(error.Error.Code.ToString());
                var response = new GatewayLinkResponse(
                    linkedPatientRepresentation,
                    error?.Error,
                    new Resp(requestId),
                    request.TransactionId);

                await gatewayClient.SendDataToGateway(PATH_ON_LINK_INIT, response, cmSuffix, correlationId);
            }
            catch (Exception exception)
            {
                Log.Error(exception, exception.StackTrace);
            }
        }

        [NonAction]
        public async Task LinkPatientCareContextFor(LinkPatientRequest request, String correlationId, string requestId)
        {
            try
            {
                var (patientLinkResponse, cmId, error) = await linkPatient
                    .VerifyAndLinkCareContext(new LinkConfirmationRequest(request.Confirmation.Token,
                        request.Confirmation.LinkRefNumber));
                var linkedPatientRepresentation = new List<LinkConfirmationRepresentation>();
                if (patientLinkResponse != null && cmId != "")
                {
                    linkedPatientRepresentation = patientLinkResponse.Patient.ToList();
                }

                var response = new GatewayLinkConfirmResponse(
                    linkedPatientRepresentation,
                    error?.Error,
                    new Resp(requestId));
                await gatewayClient.SendDataToGateway(PATH_ON_LINK_CONFIRM, response, cmId, correlationId);
            }
            catch(Exception exception)
            {
                Log.Error(exception, exception.StackTrace);
            }
        }

        [HttpPost(PATH_ON_ADD_CONTEXTS)]
        public async Task<AcceptedResult> HipLinkOnAddContexts(HipLinkContextConfirmation confirmation)
        {
            Log.Information("Link on-add-context received.");
            if (confirmation.Error != null)
                Log.Information($" Error Code:{confirmation.Error.Code}," +
                                $" Error Message:{confirmation.Error.Message}");
            else if (confirmation.Status != null)
            {
                    var error =
                        await linkPatient.VerifyAndLinkCareContexts(confirmation.Response.RequestId);
                    if (error != null)
                    {
                        Log.Error(error);
                    }
                Log.Information($" Acknowledgment Status:{confirmation.Status}");
            }
            Log.Information($" Resp RequestId:{confirmation.Response.RequestId}");
            return Accepted();
        }
    }
}
