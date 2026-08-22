using Hl7.Fhir.Model;

namespace In.ProjectEKA.HipServiceTest.DataFlow
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Mime;
    using System.Threading;
    using System.Threading.Tasks;
    using In.ProjectEKA.HipService.DataFlow;
    using Builder;
    using FluentAssertions;
    using HipService.Gateway;
    using In.ProjectEKA.HipService.DataFlow.Model;
    using In.ProjectEKA.HipService.OpenMrs;
    using Moq;
    using Moq.Protected;
    using Optional;
    using Xunit;

    [Collection("Data Flow Client Tests")]
    public class DataFlowClientTest
    {
        [Fact]
        private async Task ShouldReturnDataComponent()
        {
            const string gatewayUrl = "https://root/central-registry";
            var dataFlowNotificationClient = new Mock<DataFlowNotificationClient>(MockBehavior.Strict, null);
            var configuration = new GatewayConfiguration
            {
                Url = gatewayUrl,
                ClientId = "IN0410000183",
                ClientSecret = TestBuilder.RandomString()
            };
            var openMrsClient = new Mock<IOpenMrsClient>();
            var bahmniConfiguration = new HipService.Common.Model.BahmniConfiguration(openMrsClient.Object)
            {
                Id = "HIP_ID_123",
                Name = "HIP_NAME"
            };
            const string transactionId = "transactionId";
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
            var httpClient = new HttpClient(handlerMock.Object);
            Mock<GatewayClient> gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
            var dataRequest = TestBuilder.TraceableDataRequest(transactionId);
            var content = TestBuilder.Faker().Random.String();
            var checksum = TestBuilder.Faker().Random.Hash();
            var dataNotificationRequest = TestBuilder.DataNotificationRequest(transactionId);
            var correlationId = Uuid.Generate().ToString();
            var entries = new List<Entry>
            {
                new Entry(content, MediaTypeNames.Application.Json, checksum, "careContextReference")
            }.AsEnumerable();
            var expectedUri = new Uri("https://callback/data/notification");
            var dataFlowClient = new DataFlowClient(httpClient, dataFlowNotificationClient.Object, configuration, bahmniConfiguration, gatewayClient.Object);
            gatewayClient.Setup(client => client.Authenticate(dataRequest.CorrelationId))
                .ReturnsAsync(Option.Some("Bearer token"));
            handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK
                })
                .Verifiable();
            dataFlowNotificationClient.Setup(client =>
                client.NotifyGateway(dataRequest.CmSuffix, It.IsAny<DataNotificationRequest>(), dataRequest.CorrelationId))
                .Returns(Task.CompletedTask)
                .Callback((string cmSuffix, DataNotificationRequest request, string correlationId) =>
                {
                    dataNotificationRequest.Should().NotBeNull();
                    dataNotificationRequest.Notifier.Id.Should().Be(request.Notifier.Id);
                    dataNotificationRequest.Notifier.Type.Should().Be(request.Notifier.Type);
                    dataNotificationRequest.TransactionId.Should().Be(request.TransactionId);
                    dataNotificationRequest.StatusNotification.HipId.Should().Be(request.StatusNotification.HipId);
                    dataNotificationRequest.StatusNotification.SessionStatus.Should().Be(
                        request.StatusNotification.SessionStatus);
                });

            await dataFlowClient.SendDataToHiu(dataRequest, entries, null);

            handlerMock.Protected().Verify(
                "SendAsync",
                Times.Exactly(1),
                ItExpr.Is<HttpRequestMessage>(message => message.Method == HttpMethod.Post
                                                         && message.RequestUri == expectedUri),
                ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        private async Task ShouldNotifyGatewayAboutFailureInDataTransfer()
        {
            const string id = "ConsentManagerId";
            var dataFlowNotificationClient = new Mock<DataFlowNotificationClient>(MockBehavior.Strict, null);
            var configuration = new GatewayConfiguration
            {
                ClientId = id
            };
            var openMrsClient = new Mock<IOpenMrsClient>();
            var bahmniConfiguration = new HipService.Common.Model.BahmniConfiguration(openMrsClient.Object)
            {
                Id = "HIP_ID_123",
                Name = "HIP_NAME"
            };
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
            var httpClient = new HttpClient(handlerMock.Object);
            Mock<GatewayClient> gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
            var dataRequest = TestBuilder.TraceableDataRequest(TestBuilder.Faker().Random.Hash());
            var entries = new List<Entry>().AsEnumerable();
            var dataFlowClient = new DataFlowClient(httpClient, dataFlowNotificationClient.Object, configuration, bahmniConfiguration, gatewayClient.Object);
            gatewayClient.Setup(client => client.Authenticate(dataRequest.CorrelationId))
                .ReturnsAsync(Option.Some("Bearer token"));
            handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Throws(new Exception("Unknown exception"))
                .Verifiable();
            dataFlowNotificationClient.Setup(client => client.NotifyGateway(dataRequest.CmSuffix, It.IsAny<DataNotificationRequest>(), dataRequest.CorrelationId))
                .Returns(Task.CompletedTask);

            await dataFlowClient.SendDataToHiu(dataRequest, entries, null);

            handlerMock.Protected().Verify(
                "SendAsync",
                Times.Exactly(1),
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>());
        }
    }
}