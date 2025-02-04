using System;
using System.Collections.Generic;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.Link;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using static In.ProjectEKA.HipService.Common.Constants;
using Task = System.Threading.Tasks.Task;


namespace In.ProjectEKA.HipServiceTest.Link
{
    public class CareContextControllerTest
    {
        private readonly CareContextController careContextController;

        private readonly Mock<ILogger<CareContextController>> logger =
            new Mock<ILogger<CareContextController>>();

        private readonly Mock<GatewayClient> gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
        private readonly Mock<ICareContextService> careContextService = new Mock<ICareContextService>();
        private readonly Mock<ILinkPatientRepository> linkPatientRepository = new Mock<ILinkPatientRepository>();
        
        public CareContextControllerTest()
        {
            careContextController =
                new CareContextController(careContextService.Object, linkPatientRepository.Object);
        }

        [Fact]
        private void ShouldAddContext()
        {
            var requestId = Guid.NewGuid();
            var cmSuffix = "sbx";
            var careContextRepresentation = new CareContextRepresentation("anc", "xyz");
            var careContexts = new List<CareContextRepresentation>();
            careContexts.Add(careContextRepresentation);
            var error = new Error(ErrorCode.GatewayTimedOut, "Gateway timed out");
            var resp = new Resp("123");
            var correlationId = Uuid.Generate().ToString();
            var linkConfirmationRepresentation =
                new LinkConfirmationRepresentation("1234", "qwqwqw", careContexts, "Prescription", 1);

            var gatewayAddContextsRequestRepresentation =
                new GatewayAddContextsRequestRepresentation("doctest@sbx",new List<LinkConfirmationRepresentation>(){linkConfirmationRepresentation});

            var onAddContextRequest =
                new HipLinkContextConfirmation( "doctest@sbx","Successfully Linked care context", error,
                    resp);
            var addContextRequest = new NewContextRequest("abc", "pqr", careContexts, "abcd@sbx");

            careContextService.Setup(a => a.AddContextsResponse(addContextRequest,"sbx",requestId))
                .Returns(Task.FromResult(new Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>
                    (gatewayAddContextsRequestRepresentation, null)));

            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_ADD_PATIENT_CONTEXTS,
                            gatewayAddContextsRequestRepresentation, cmSuffix, correlationId,null,null,null))
                .Returns(Task.CompletedTask)
                .Callback<string, GatewayAddContextsRequestRepresentation, string, string,string, string,string>
                ((path, gr, suffix, corId,hipId,requestId,linkToken)
                    => careContextController.Accepted(onAddContextRequest));
        }

        [Fact]
        private void ShouldNotify()
        {
            var error = new Error(ErrorCode.GatewayTimedOut, "Gateway timed out");
            var resp = new Resp("123");
            var careContextRepresentation = new CareContextRepresentation("anc", "xyz","VISIT",new List<HiType>(){HiType.Prescription});

            var hiTypes = new List<string>();
            hiTypes.Add("Prescription");
            var notifyContextRequest = new NewContextRequest("abc", "swjs", new List<CareContextRepresentation>(){careContextRepresentation},"doctest@sbx");
            var onNotifyContextRequest =
                new HipLinkContextConfirmation("doctest@sbx", "Successfully Linked care context", error,
                    resp);
            var patient = new NotificationPatientContext("12");
            var notificationCareContext = new NotificationCareContext("abc", "qqwq");
            var hipReference = new NotificationContextHip("1212");
            var gatewayNotificationContextsRequestRepresentation =
                new GatewayNotificationContextRepresentation(
                    new NotificationContext(patient, notificationCareContext, hiTypes, new DateTime().ToString(DateTimeFormat), hipReference));

            careContextService.Setup(a => a.NotificationContextResponse(notifyContextRequest, careContextRepresentation))
                .Returns(new Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation>
                    (gatewayNotificationContextsRequestRepresentation, null));

            var cmSuffix = "sbx";
            var correlationId = Uuid.Generate().ToString();


            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_NOTIFY_PATIENT_CONTEXTS,
                            gatewayNotificationContextsRequestRepresentation, cmSuffix, correlationId,null,null,null))
                .Returns(Task.CompletedTask)
                .Callback<string, GatewayNotificationContextRepresentation, string, string,string, string,string>
                ((path, gr, suffix, corId,hipId,requestId,linkToken)
                    => careContextController.Accepted(onNotifyContextRequest));
        }

        [Fact]
        private void ShouldCallAddContextApi()
        {
            var careContexts = new List<CareContextRepresentation>
            {
                new CareContextRepresentation("3", "IPD")
            };
            var newContextRequest = new NewContextRequest("GAN204041", "some",
                careContexts, "hinapatel@sbx");
            var linkedCareContexts = new List<string> {"OPD", "Special OPD"};

            linkPatientRepository.Setup(e => e.GetLinkedCareContextsOfPatient(newContextRequest.PatientReferenceNumber))
                .ReturnsAsync(new Tuple<List<string>, Exception>(linkedCareContexts, null));
            careContextService.Setup(e => e.IsLinkedContext(linkedCareContexts, careContexts[0].Display))
                .Returns(false);
            careContextController.PassContext(newContextRequest);

            careContextService.Verify(a => a.CallAddContext(newContextRequest), Times.Exactly(1));
        }
    }
}