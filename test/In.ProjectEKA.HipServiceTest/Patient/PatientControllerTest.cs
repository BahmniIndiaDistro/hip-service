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
            var hipPatientNotifyConfirmation = new HipPatientNotifyConfirmation(Guid.NewGuid().ToString(), timestamp.ToString(DateTimeFormat),
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
            var timestamp = DateTime.Now.ToUniversalTime().ToString();
            var identifier = new Identifier("MOBILE", "9999999999");
            var address = new Address("string", "string", "string", "string");
            var patient = new PatientDemographics("test t", "M", "test@sbx", address, 2000, 0, 0,"91-1184-2524-4233","9123456789");
            var profile = new Profile( patient);
            var shareProfileMetadata = new ShareProfileMetadata("12345", "1","test@hpr.abdm","71.254","78.325");
            var shareProfileRequest = new ShareProfileRequest("PROFILE_SHARE", shareProfileMetadata, profile);
            var correlationId = Uuid.Generate().ToString();
            var cmSuffix = "ncg";
            _patientProfileService.Setup(d => d.IsValidRequest(shareProfileRequest)).Returns(true);
            var profileShareConfirmation = new ProfileShareConfirmation(new ProfileShareAcknowledgement(
                    Status.SUCCESS.ToString(),"test@sbx",new ProfileShareAckProfile(shareProfileMetadata.Context,"1","1800")),null,new Resp(Guid.NewGuid().ToString()));
            _gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                            profileShareConfirmation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));
            Assert.Equal(
                ((Microsoft.AspNetCore.Mvc.AcceptedResult) _patientController
                    .StoreDetails(correlationId, shareProfileRequest,requestId,timestamp).Result).StatusCode,
                StatusCodes.Status202Accepted);
        }

        [Fact]
        private void ShouldThrowBadRequest()
        {
            var requestId = Guid.NewGuid().ToString();
            var timestamp = DateTime.Now.ToUniversalTime().ToString();
            var identifier = new Identifier("MOBILE", "9999999999");
            var address = new Address("string", "string", "string", "string");
            var patient = new PatientDemographics(null, "M", "test@sbx", address, 2000, 0, 0,
                "91-1184-2524-4233","9123456789");
            var shareProfileMetadata = new ShareProfileMetadata("12345", "1","test@hpr.abdm","71.254","78.325");
            var profile = new Profile(patient);
            var shareProfileRequest = new ShareProfileRequest("PROFILE_SHARE", shareProfileMetadata, profile);
            var correlationId = Uuid.Generate().ToString();
            var cmSuffix = "ncg";
            _patientProfileService.Setup(d => d.IsValidRequest(shareProfileRequest)).Returns(false);
            var profileShareConfirmation = new ProfileShareConfirmation(
                new ProfileShareAcknowledgement(
                    Status.SUCCESS.ToString(),"test@sbx",new ProfileShareAckProfile(shareProfileMetadata.Context,"1","1800")),null, new Resp(Guid.NewGuid().ToString()));
            _gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_PROFILE_ON_SHARE,
                            profileShareConfirmation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));
            Assert.Equal(
                ((Microsoft.AspNetCore.Mvc.BadRequestResult) _patientController
                    .StoreDetails(correlationId, shareProfileRequest,requestId,timestamp).Result).StatusCode,
                StatusCodes.Status400BadRequest);
        }
    }
}