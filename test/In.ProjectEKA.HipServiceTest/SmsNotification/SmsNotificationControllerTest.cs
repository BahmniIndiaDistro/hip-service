using System;
using System.Net.Http;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.SmsNotification;
using Microsoft.Extensions.Logging;
using Moq;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.SmsNotification.Model;
using Microsoft.AspNetCore.Mvc;
using Xunit;
using static In.ProjectEKA.HipService.Common.Constants;
using Task = System.Threading.Tasks.Task;


namespace In.ProjectEKA.HipServiceTest.SmsNotification
{
    public class SmsNotificationControllerTest
    {
        private readonly SmsNotificationController smsNotificationController;

        private readonly Mock<ILogger<SmsNotificationController>> logger =
            new Mock<ILogger<SmsNotificationController>>();

        private readonly Mock<GatewayClient> gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
        private readonly Mock<ISmsNotificationService> smsNotificationService = new Mock<ISmsNotificationService>();

        private readonly GatewayConfiguration gatewayConfiguration = new GatewayConfiguration()
        {
            CmSuffix = "sbx"
        };

        public SmsNotificationControllerTest()
        {
            smsNotificationController = new SmsNotificationController(gatewayClient.Object, logger.Object,
                new SmsNotificationService(), new BahmniConfiguration(), gatewayConfiguration, new HttpClient(),
                new OpenMrsConfiguration());
        }

        [Fact]
        private void shouldSendSMSNotificationForNewCareContextAndReturnAccepted()
        {
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var error = new Error(ErrorCode.GatewayTimedOut, "Gateway timed out");
            var resp = new Resp("123");
            var cmSuffix = "sbx";
            var correlationId = Uuid.Generate().ToString();
            var smsNotificationAcknowledgement = new SmsNotificationAcknowledgement("success");
            var phoneNo = "123456789";
            var smsNotifyHip = new SmsNotifyHip("anc", "123");

            var onSmsContextRequest =
                new SmsContextConfirmation(requestId.ToString(), timeStamp, smsNotificationAcknowledgement, error,
                    resp);

            var gatewaySmsNotifyRequestRepresentation = new GatewaySmsNotifyRepresentation(requestId, timeStamp,
                new HipService.SmsNotification.Model.SmsNotification(phoneNo, smsNotifyHip));

            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_SMS_NOTIFY,
                            gatewaySmsNotifyRequestRepresentation, cmSuffix, correlationId,null,null,null))
                .Returns(Task.CompletedTask)
                .Callback<string, GatewaySmsNotifyRepresentation, string, string,string, string,string>
                ((path, gr, suffix, corId,hipId,requestId,linkToken)
                    => smsNotificationController.Accepted(onSmsContextRequest));
        }

        [Fact]
        private void shouldSendSMSNotificationForNewCareContextAndReturnRejected()
        {
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var cmSuffix = "abc";
            var correlationId = Uuid.Generate().ToString();
            var phoneNo = "123456789";
            var smsNotifyHip = new SmsNotifyHip("anc", "123");

            var gatewaySmsNotifyRequestRepresentation = new GatewaySmsNotifyRepresentation(requestId, timeStamp,
                new HipService.SmsNotification.Model.SmsNotification(phoneNo, smsNotifyHip));


            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_SMS_NOTIFY,
                            gatewaySmsNotifyRequestRepresentation, cmSuffix, correlationId,null,null,null))
                .Returns(Task.CompletedTask)
                .Callback<string, GatewaySmsNotifyRepresentation, string, string,string, string,string>
                ((path, gr, suffix, corId,hipId,requestId,linkToken)
                    => smsNotificationController.Problem());
        }

        [Fact]
        private bool shouldReturnGatewayRequestObject()
        {
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var phoneNo = "123456789";
            var smsNotifyHip = new SmsNotifyHip("anc", "123");

            var gatewaySmsNotifyRequestRepresentation = new GatewaySmsNotifyRepresentation(requestId, timeStamp,
                new HipService.SmsNotification.Model.SmsNotification(phoneNo, smsNotifyHip));

            if (gatewaySmsNotifyRequestRepresentation != null)
                return true;
            return false;
        }

        [Fact]
        private bool shouldReturnOnSmsNotifyRequest()
        {
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var error = new Error(ErrorCode.GatewayTimedOut, "Gateway timed out");
            var resp = new Resp("123");
            var correlationId = Uuid.Generate().ToString();
            var smsNotificationAcknowledgement = new SmsNotificationAcknowledgement("success");

            var onSmsNotify =
                new OnSmsNotifyRequest( "Ok", error, resp);
            if (onSmsNotify != null)
                return true;
            return false;
        }

        [Fact]
        private bool shouldReturnSmsNotification()
        {
            var phoneNo = "123456789";
            var smsNotifyHip = new SmsNotifyHip("anc", "123");

            var smsNotification =
                new HipService.SmsNotification.Model.SmsNotification(phoneNo,  smsNotifyHip);
            if (smsNotification != null)
                return true;
            return false;
        }

        [Fact]
        private AcceptedResult shouldReturnOnSmsRequestObjectAndReturnAccepted()
        {
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var error = new Error(ErrorCode.GatewayTimedOut, "Gateway timed out");
            var resp = new Resp("123");
            var correlationId = Uuid.Generate().ToString();
            var smsNotificationAcknowledgement = new SmsNotificationAcknowledgement("success");

            var onSmsNotifyRequest =
                new OnSmsNotifyRequest("Ok", error, resp);

            return new AcceptedResult();
        }
    }
}