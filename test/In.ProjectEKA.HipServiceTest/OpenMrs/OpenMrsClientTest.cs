using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using In.ProjectEKA.HipService.OpenMrs;
using Moq;
using Moq.Protected;
using Xunit;
namespace In.ProjectEKA.HipServiceTest.OpenMrs
{
    [Collection("OpenMrs Gateway Client Tests")]
    public class OpenMrsClientTest
    {
        [Fact]
        public void ShouldThrowErrorIfGetAsyncReturnsNonSuccessStatusCode()
        {
            //Given
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
            var httpClient = new HttpClient(handlerMock.Object);
            var openmrsConfiguration = new OpenMrsConfiguration
            {
                Url = "https://someurl/openmrs/",
                Username = "someusername",
                Password = "somepassword"
            };
            var openmrsClient = new OpenMrsClient(httpClient, openmrsConfiguration);
            handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync( new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.InternalServerError,
                    Content = new StringContent("some error message"),
                    RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://someurl/openmrs/path/to/resource")
                })
                .Verifiable();

            //When
            Func<Task> getAsyncMethod = async () => { await openmrsClient.GetAsync("path/to/resource").ConfigureAwait(false); };

            //Then
            getAsyncMethod.Should().Throw<OpenMrsConnectionException>();
        }

        [Fact]
        public void ShouldThrowExceptionAndLogIfAnyExceptionIsThrown()
        {
            //Given
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
            var httpClient = new HttpClient(handlerMock.Object);
            var openmrsConfiguration = new OpenMrsConfiguration
            {
                Url = "https://someurl/openmrs/",
                Username = "someusername",
                Password = "somepassword"
            };
            var openmrsClient = new OpenMrsClient(httpClient, openmrsConfiguration);
            handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ThrowsAsync(new Exception("some message here"))
                .Verifiable();

            //When
            Func<Task> getAsyncMethod = async () => { await openmrsClient.GetAsync("path/to/resource"); };
            //Then
            getAsyncMethod.Should().Throw<Exception>();
        }

        [Theory]
        [InlineData("path/to/resource")]
        // [InlineData("/path/to/resource")]
        public async Task ShouldInterrogateTheRightDataSource(string patientDiscoveryPath)
        {
            //Given
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Loose);
            var httpClient = new HttpClient(handlerMock.Object);
            var openmrsConfiguration = new OpenMrsConfiguration
            {
                Url = "https://someurl/openmrs/",
                Username = "someusername",
                Password = "somepassword"
            };
            var openmrsClient = new OpenMrsClient(httpClient, openmrsConfiguration);
            var wasCalledWithTheRightUri = false;
            handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                    .Callback<HttpRequestMessage, CancellationToken>((request, token) =>
                    {
                        wasCalledWithTheRightUri = request.RequestUri != null
                            && request.RequestUri.ToString().Contains("path/to/resource");
                    })
                    .ReturnsAsync(new HttpResponseMessage
                    {
                        StatusCode = HttpStatusCode.OK,
                        RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://someurl/openmrs/path/to/resource")
                    })
                    .Verifiable();

                //When
                await openmrsClient.GetAsync(patientDiscoveryPath);
                wasCalledWithTheRightUri.Should().BeTrue();
        }

    }
}