using In.ProjectEKA.HipService.Patient;
using In.ProjectEKA.HipService.Patient.Model;
using Task = System.Threading.Tasks.Task;
using System;
using System.Collections.Generic;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Gateway;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;
using Address = In.ProjectEKA.HipService.Patient.Model.Address;
using Identifier = In.ProjectEKA.HipService.UserAuth.Model.Identifier;

namespace In.ProjectEKA.HipServiceTest.Patient
{
    using static Constants;

    public class PatientControllerTest
    {
        private readonly PatientController _patientController;

        private readonly Mock<IPatientNotificationService> _patientNotificationService =
            new Mock<IPatientNotificationService>();

        private readonly Mock<IPatientProfileService> _patientProfileService =
            new Mock<IPatientProfileService>();

        private readonly Mock<GatewayClient> _gatewayClient = new Mock<GatewayClient>(MockBehavior.Loose, null, null);
        
        private readonly GatewayConfiguration _gatewayConfiguration = new GatewayConfiguration()
        {
            CmSuffix = "sbx"
        };


        public PatientControllerTest()
        {
            _patientController = new PatientController(_gatewayClient.Object,
                _patientNotificationService.Object, _gatewayConfiguration, _patientProfileService.Object);
        }


        [Fact]
        private void ShouldNotifyHip()
        {
            var requestId = Guid.NewGuid();
            var timestamp = DateTime.Now.ToUniversalTime();
            var patient = new HipNotifyPatient("test@sbx");
            var notification = new PatientNotification(HipService.Patient.Model.Action.DELETED, patient);
            var hipPatientStatusNotification = new HipPatientStatusNotification(requestId, timestamp, notification);
            var correlationId = Uuid.Generate().ToString();
            var cmSuffix = "ncg";
            var hipPatientNotifyConfirmation = new HipPatientNotifyConfirmation(Guid.NewGuid().ToString(), timestamp,
                new PatientNotifyAcknowledgement(Status.SUCCESS.ToString()),
                null, new Resp(requestId.ToString()));
            _gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_PATIENT_ON_NOTIFY,
                            hipPatientNotifyConfirmation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));
            Assert.Equal(_patientController.NotifyHip(correlationId, hipPatientStatusNotification).Result.StatusCode,
                StatusCodes.Status202Accepted);
        }

        [Fact]
        private void ShouldSaveAPatient()
        {
            var requestId = Guid.NewGuid().ToString();
            var timestamp = DateTime.Now.ToUniversalTime();
            var identifier = new Identifier("MOBILE", "9999999999");
            var address = new Address("string", "string", "string", "string");
            var patient = new PatientDemographics("test t", "M", "test@sbx", address, 2000, 0, 0,
                new List<Identifier>() {identifier}, "1234-5678");
            var profile = new Profile("12345", patient);
            var shareProfileRequest = new ShareProfileRequest(requestId, timestamp, profile);
            var correlationId = Uuid.Generate().ToString();
            var cmSuffix = "ncg";
            _patientProfileService.Setup(d => d.IsValidRequest(shareProfileRequest)).Returns(true);
            var profileShareConfirmation = new ProfileShareConfirmation(
                Guid.NewGuid().ToString(),
                DateTime.Now.ToUniversalTime(),
                new ProfileShareAcknowledgement("test@sbx",
                    Status.SUCCESS.ToString(),"1"), null,
                new Resp(requestId));
            _gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                            profileShareConfirmation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));
            Assert.Equal(
                ((Microsoft.AspNetCore.Mvc.AcceptedResult) _patientController
                    .StoreDetails(correlationId, shareProfileRequest).Result).StatusCode,
                StatusCodes.Status202Accepted);
        }

        [Fact]
        private void ShouldThrowBadRequest()
        {
            var requestId = Guid.NewGuid().ToString();
            var timestamp = DateTime.Now.ToUniversalTime();
            var identifier = new Identifier("MOBILE", "9999999999");
            var address = new Address("string", "string", "string", "string");
            var patient = new PatientDemographics(null, "M", "test@sbx", address, 2000, 0, 0,
                new List<Identifier>() {identifier}, "1234-5678");
            var profile = new Profile("12345", patient);
            var shareProfileRequest = new ShareProfileRequest(requestId, timestamp, profile);
            var correlationId = Uuid.Generate().ToString();
            var cmSuffix = "ncg";
            _patientProfileService.Setup(d => d.IsValidRequest(shareProfileRequest)).Returns(false);
            var profileShareConfirmation = new ProfileShareConfirmation(
                Guid.NewGuid().ToString(),
                DateTime.Now.ToUniversalTime(),
                new ProfileShareAcknowledgement("test@sbx",
                    Status.SUCCESS.ToString(),"1"), null,
                new Resp(requestId));
            _gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                            profileShareConfirmation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));
            Assert.Equal(
                ((Microsoft.AspNetCore.Mvc.BadRequestResult) _patientController
                    .StoreDetails(correlationId, shareProfileRequest).Result).StatusCode,
                StatusCodes.Status400BadRequest);
        }
    }
}