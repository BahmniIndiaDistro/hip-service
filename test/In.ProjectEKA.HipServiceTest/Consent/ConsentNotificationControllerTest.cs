using Hl7.Fhir.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Gateway;

namespace In.ProjectEKA.HipServiceTest.Consent
{
    using System;
    using System.Threading.Tasks;
    using Bogus;
    using Builder;
    using FluentAssertions;
    using Hangfire;
    using Hangfire.Common;
    using Hangfire.States;
    using HipService.Common.Model;
    using HipService.Consent;
    using HipService.Consent.Model;
    using In.ProjectEKA.HipService.Gateway.Model;
    using Microsoft.AspNetCore.Http;
    using Moq;
    using Xunit;

    [Collection("Consent Notification Controller Tests")]
    public class ConsentNotificationControllerTest
    {
        private readonly Mock<IConsentRepository> consentRepository;
        private readonly ConsentNotificationController consentNotificationController;
        private readonly Mock<IBackgroundJobClient> backgroundJobClient;
        private readonly Mock<GatewayClient> gatewayClient;
        private ConsentArtefactRepresentation consentNotification;
        private Func<Consent, bool> verifyActualConsentEqualsExpected;

        public ConsentNotificationControllerTest()
        {
            var correlationId = Uuid.Generate().ToString();
            consentRepository = new Mock<IConsentRepository>();
            backgroundJobClient = new Mock<IBackgroundJobClient>();
            gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
            consentNotificationController = new ConsentNotificationController(consentRepository.Object,
                backgroundJobClient.Object,
                gatewayClient.Object);

            SetupConsentNotification(ConsentStatus.GRANTED);

            verifyActualConsentEqualsExpected =
                (actual) =>
                {
                    var expected = consentNotification.Notification;

                    return actual.ConsentArtefactId == expected.ConsentDetail.ConsentId
                        && actual.ConsentArtefact == expected.ConsentDetail
                        && actual.Signature == expected.Signature
                        && actual.Status == expected.Status
                        && actual.ConsentManagerId == expected.ConsentId;
                };

            gatewayClient
                .Setup(g =>
                    g.SendDataToGateway(
                        It.IsAny<string>(),
                        It.IsAny<GatewayConsentRepresentation>(),
                        It.IsAny<string>(),
                        It.IsAny<string>(),null,null,null))
                .Returns(Task.Run(() => { }));
        }

        private void SetupConsentNotification(ConsentStatus consentStatus)
        {
            const string consentMangerId = "consentMangerId";
            var notification = TestBuilder.Notification(consentStatus);
            var faker = new Faker();
            consentNotification = new ConsentArtefactRepresentation(notification);
            var consent =
                new Consent(notification.ConsentDetail.ConsentId,
                    notification.ConsentDetail,
                    notification.Signature,
                    consentStatus,
                    consentMangerId);
            consentRepository.Setup(x => x.AddAsync(consent));
            consentRepository
                .Setup(x => x.GetFor(It.IsAny<string>()))
                .Returns(System.Threading.Tasks.Task.FromResult(consent));
        }

        [Fact]
        private void ShouldEnqueueConsentNotificationAndReturnAccepted()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            var timestamp = DateTime.Now.ToString();
           var result = consentNotificationController.ConsentNotification(correlationId, requestId, timestamp, consentNotification);

            backgroundJobClient.Verify(client => client.Create(
                It.Is<Job>(job => job.Method.Name == "StoreConsent" && job.Args[0] == consentNotification),
                It.IsAny<EnqueuedState>()));
            consentRepository.Verify();
            result.StatusCode.Should().Be(StatusCodes.Status202Accepted);
        }

        [Fact]
        async void ShouldStoreConsentArtefact()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            await consentNotificationController.StoreConsent(consentNotification,correlationId,requestId);

            consentRepository.Verify(cr => cr.AddAsync(
                It.Is<Consent>(c => verifyActualConsentEqualsExpected(c))),
                Times.Once);
            consentRepository.Verify(cr =>
                cr.UpdateAsync(It.IsAny<string>(), It.IsAny<ConsentStatus>()), Times.Never);
        }

        [Theory]
        [InlineData(ConsentStatus.DENIED)]
        [InlineData(ConsentStatus.EXPIRED)]
        [InlineData(ConsentStatus.REQUESTED)]
        [InlineData(ConsentStatus.REVOKED)]
        async void ShouldUpdateConsentArtefact(ConsentStatus consentStatus)
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            SetupConsentNotification(consentStatus);

            await consentNotificationController.StoreConsent(consentNotification,correlationId,requestId);

            consentRepository.Verify(cr => cr.UpdateAsync(
                    consentNotification.Notification.ConsentId,
                    consentStatus),
                Times.Once);
            consentRepository.Verify(cr => cr.AddAsync(It.IsAny<Consent>()), Times.Never);
        }

        [Fact]
        async void ShouldInvokeGatewayWhenRevokingConsent()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            SetupConsentNotification(ConsentStatus.REVOKED);

            await consentNotificationController.StoreConsent(consentNotification,correlationId,requestId);

            gatewayClient.Verify(g => g.SendDataToGateway(
                    Constants.PATH_CONSENT_ON_NOTIFY,
                        It.Is<GatewayConsentRepresentation>(
                            c =>
                                c.Acknowledgement.ConsentId == consentNotification.Notification.ConsentId
                                && c.Response.RequestId == requestId),
                        consentNotification.Notification.ConsentDetail.ConsentManager.Id,
                                correlationId,null,null,null),
                Times.Once);
        }
    }
}