using System.Linq;

namespace In.ProjectEKA.HipService.Discovery
{
    using System;
    using System.Net;
    using System.Threading.Tasks;
    using Gateway;
    using Gateway.Model;
    using static Common.Constants;
    using Hangfire;
    using HipLibrary.Patient.Model;
    using Logger;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using static In.ProjectEKA.HipService.Discovery.DiscoveryReqMap;
    using Common;


    [Authorize]
    [Route(PATH_CARE_CONTEXTS_DISCOVER)]
    [ApiController]
    public class CareContextDiscoveryController : Controller
    {
        private const string SuccessMessage = "Patient record with one or more care contexts found";
        private const string ErrorMessage = "No Matching Record Found or More than one Record Found";

        private readonly IPatientDiscovery patientDiscovery;
        private readonly IGatewayClient gatewayClient;
        private readonly IBackgroundJobClient backgroundJob;
        private readonly ILogger<CareContextDiscoveryController> logger;

        public CareContextDiscoveryController(IPatientDiscovery patientDiscovery,
            IGatewayClient gatewayClient,
            IBackgroundJobClient backgroundJob, ILogger<CareContextDiscoveryController> logger)
        {
            this.patientDiscovery = patientDiscovery;
            this.gatewayClient = gatewayClient;
            this.backgroundJob = backgroundJob;
            this.logger = logger;
        }

        public AcceptedResult DiscoverPatientCareContexts(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromBody] DiscoveryRequest request)
        {
            Log.Information($"discovery request received for {request.Patient.Id} with {request.RequestId}.");
            Log.Information("Started Execution");
            Log.Information("calling GetPatientCareContext Method, Patient Name -> " + request.Patient.Name);
            Log.Information("Correlation Id -----> " + correlationId);
            backgroundJob.Enqueue(() => GetPatientCareContext(request, correlationId));
            return Accepted();
        }

        [NonAction]
        public async Task GetPatientCareContext(DiscoveryRequest request, string correlationId)
        {
            Log.Information("In GetPatientCareContext Method -----> ");
            var patientId = request.Patient.Id;
            Log.Information("Patient Id -----> " + patientId);
            var cmSuffix = patientId.Substring(patientId.LastIndexOf("@", StringComparison.Ordinal) + 1);
            Log.Information("CM suffix -----> " + cmSuffix);
            try
            {
                var (response, error) = await patientDiscovery.PatientFor(request);
                Log.Information("PatientFor executed successfully" + response);
                var gatewayDiscoveryRepresentation = new GatewayDiscoveryRepresentation(
                    response?.Patient,
                    Guid.NewGuid(),
                    DateTime.Now.ToUniversalTime().ToString(DateTimeFormat),
                    request.TransactionId, //TODO: should be reading transactionId from contract
                    error?.Error,
                    new DiscoveryResponse(request.RequestId,
                        error == null ? HttpStatusCode.OK : HttpStatusCode.NotFound,
                        error == null ? SuccessMessage : ErrorMessage));
                if (!PatientInfoMap.ContainsKey(patientId))
                {
                    PatientInfoMap.Add(patientId, request.Patient);
                }
                
                Log.Information("new GatewayDiscoveryRepresentation" + gatewayDiscoveryRepresentation);
                Log.Information("Sending data to gateway");
                Log.Information($"Response about to be send for {request.RequestId} with {@response?.Patient}");
                await gatewayClient.SendDataToGateway(PATH_ON_DISCOVER, gatewayDiscoveryRepresentation, cmSuffix,
                    correlationId);
            }
            catch (Exception exception)
            {
                var gatewayDiscoveryRepresentation = new GatewayDiscoveryRepresentation(
                    null,
                    Guid.NewGuid(),
                    DateTime.Now.ToUniversalTime().ToString(DateTimeFormat),
                    request.TransactionId, //TODO: should be reading transactionId from contract
                    new Error(ErrorCode.ServerInternalError, "Unreachable external service"),
                    new DiscoveryResponse(request.RequestId, HttpStatusCode.InternalServerError,
                        "Unreachable external service"));
                await gatewayClient.SendDataToGateway(PATH_ON_DISCOVER, gatewayDiscoveryRepresentation, cmSuffix,
                    correlationId);
                logger.LogError(LogEvents.Discovery, exception, $"Error happened for {request.RequestId}");
            }
        }
    }
}