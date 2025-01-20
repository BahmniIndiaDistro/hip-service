using System.Net.WebSockets;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Discovery.Mapper;

namespace In.ProjectEKA.HipServiceTest.Discovery
{
    using System;
    using System.Linq;
    using System.Net;
    using Hangfire;
    using In.ProjectEKA.HipService.Gateway;
    using In.ProjectEKA.HipService.Gateway.Model;
    using System.Collections.Generic;
    using HipLibrary.Patient.Model;
    using In.ProjectEKA.HipService.Discovery;
    using Moq;
    using Xunit;
    using System.Net.Http.Headers;
    using Common.TestServer;
    using Builder;
    using FluentAssertions;
    using Hangfire.Common;
    using Hangfire.States;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Logging;

    public class PatientControllerTest
    {
        private readonly Mock<IPatientDiscovery> patientDiscoveryMock;
        private readonly CareContextDiscoveryController careContextDiscoveryController;
        private readonly Dictionary<string, GatewayDiscoveryRepresentation> responsesSentToGateway;
        private readonly Dictionary<string, Job> backgroundJobs;
        
        private static readonly User Krunal = User.Krunal;
        private static readonly User JohnDoe = User.JohnDoe;

        public PatientControllerTest()
        {
            patientDiscoveryMock = new Mock<IPatientDiscovery>();
            var gatewayClientMock = new Mock<IGatewayClient>();
            var backgroundJobClientMock = new Mock<IBackgroundJobClient>();
            var logger = new Mock<ILogger<CareContextDiscoveryController>>();

            responsesSentToGateway = new Dictionary<string, GatewayDiscoveryRepresentation>();
            backgroundJobs = new Dictionary<string, Job>();

            careContextDiscoveryController = new CareContextDiscoveryController(patientDiscoveryMock.Object,
                gatewayClientMock.Object, backgroundJobClientMock.Object, logger.Object);

            SetupGatewayClientToSaveAllSentDiscoveryIntoThisList(gatewayClientMock, responsesSentToGateway);
            SetupBackgroundJobClientToSaveAllCreatedJobsIntoThisList(backgroundJobClientMock, backgroundJobs);
        }

        [Theory]
        [InlineData(HttpStatusCode.Accepted)]
        [InlineData(HttpStatusCode.BadRequest, "PatientName")]
        [InlineData(HttpStatusCode.BadRequest, "PatientGender")]
        [InlineData(HttpStatusCode.BadRequest, "PatientName", "PatientGender")]
        [InlineData(HttpStatusCode.BadRequest, "TransactionId")]
        [InlineData(HttpStatusCode.BadRequest, "PatientId")]
        private async void DiscoverPatientCareContexts_ReturnsExpectedStatusCode_WhenRequestIsSentWithParameters(
            HttpStatusCode expectedStatusCode, params string[] missingRequestParameters)
        {
            var _server = new Microsoft.AspNetCore.TestHost.TestServer(new WebHostBuilder().UseStartup<TestStartup>());
            var _client = _server.CreateClient();
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
            _client.DefaultRequestHeaders.Add(Constants.REQUEST_ID, Uuid.Generate().ToString());
            var requestContent = new DiscoveryRequestPayloadBuilder()
                .WithMissingParameters(missingRequestParameters)
                .BuildSerializedFormat();

            var response =
                await _client.PostAsync(
                    Constants.PATH_CARE_CONTEXTS_DISCOVER,
                    requestContent);

            response.StatusCode.Should().Be(expectedStatusCode);
        }

        [Fact]
        private async void ShouldThrowBadRequest_WhenRequestIdHeaderIsNotSent()
        {
            var _server = new Microsoft.AspNetCore.TestHost.TestServer(new WebHostBuilder().UseStartup<TestStartup>());
            var _client = _server.CreateClient();
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
            var requestContent = new DiscoveryRequestPayloadBuilder()
                .BuildSerializedFormat();

            var response =
                await _client.PostAsync(
                    Constants.PATH_CARE_CONTEXTS_DISCOVER,
                    requestContent);

            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        #region Describe everything that should be sent by scenario

        [Fact]
        public async void ShouldSendWhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheSentResponseShouldContainTheFoundPatient(actualResponse, discoveryRepresentation.Patient);
            AndTheResponseShouldContainTheMatchFields(actualResponse,
                discoveryRepresentation.Patient.MatchedBy.ToList());
            AndTheResponseShouldContainTheTransactionId(actualResponse, discoveryRequest);
            AndTheResponseShouldContainTheExpectedStatus(actualResponse, discoveryRequest, HttpStatusCode.OK,
                "Patient record with one or more care contexts found");
            AndTheResponseShouldNotContainAnyError(actualResponse);
        }

        [Theory]
        [InlineData(ErrorCode.NoPatientFound, HttpStatusCode.NotFound,
            "No Matching Record Found or More than one Record Found")]
        [InlineData(ErrorCode.MultiplePatientsFound, HttpStatusCode.NotFound,
            "No Matching Record Found or More than one Record Found")]
        public async void ShouldSendWhenNoSingleMatchWasFound(string errorCode, HttpStatusCode expectedStatusCode,
            string expectedResponseDescription)
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldNotContainAnyPatientDetails(actualResponse);
            AndTheResponseShouldNotContainAyMatchFields(actualResponse);
            AndTheResponseShouldContainTheTransactionId(actualResponse, discoveryRequest);
            AndTheResponseShouldContainTheExpectedStatus(actualResponse, discoveryRequest, expectedStatusCode,
                expectedResponseDescription);
            AndTheResponseShouldContainTheErrorDetails(actualResponse, errorRepresentation);
        }

        [Fact]
        public async void ShouldSendBahmniIsDownOrAnExternalSystem()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            ButTheDataSourceIsNotReachable(out ErrorRepresentation errorRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldNotContainAnyPatientDetails(actualResponse);
            AndTheResponseShouldNotContainAyMatchFields(actualResponse);
            AndTheResponseShouldContainTheTransactionId(actualResponse, discoveryRequest);
            AndTheResponseShouldContainTheExpectedStatus(actualResponse, discoveryRequest,
                HttpStatusCode.InternalServerError, "Unreachable external service");
            AndTheResponseShouldContainTheErrorDetails(actualResponse, errorRepresentation);
        }

        #endregion

        #region Unit block when a user find its record

        [Fact]
        public async void ShouldSendTheFoundPatientDetailsWhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheSentResponseShouldContainTheFoundPatient(actualResponse, discoveryRepresentation.Patient);
        }

        [Fact]
        public async void ShouldSendTheListOfMatchedFieldsWhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheMatchFields(actualResponse,
                discoveryRepresentation.Patient.MatchedBy.ToList());
        }

        [Fact]
        public async void ShouldSendTheTransactionIdWhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheTransactionId(actualResponse, discoveryRequest);
        }

        [Fact]
        public async void ShouldSendTheResponseStatusWith200WhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheExpectedStatus(actualResponse, discoveryRequest, HttpStatusCode.OK,
                "Patient record with one or more care contexts found");
        }

        [Fact]
        public async void ShouldNotSendAnyErrorWhenAPatientWasFound()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(Krunal, out DiscoveryRequest discoveryRequest);
            AndThisPatientMatchASingleRegisteredPatient(Krunal, new[] {"name", "gender"},
                out DiscoveryRepresentation discoveryRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldNotContainAnyError(actualResponse);
        }

        #endregion

        #region Unit block when a user do not find his record

        [Theory]
        [InlineData(ErrorCode.NoPatientFound)]
        [InlineData(ErrorCode.MultiplePatientsFound)]
        public async void ShouldNotSendFoundPatientDetailsWhenNoPatientWasFound(string errorCode)
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldNotContainAnyPatientDetails(actualResponse);
        }

        [Theory]
        [InlineData(ErrorCode.NoPatientFound)]
        [InlineData(ErrorCode.MultiplePatientsFound)]
        public async void ShouldNotSendAnyMatchedFieldWhenNoPatientWasFound(string errorCode)
        {
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldNotContainAyMatchFields(actualResponse);
        }

        [Theory]
        [InlineData(ErrorCode.NoPatientFound)]
        [InlineData(ErrorCode.MultiplePatientsFound)]
        public async void ShouldSendTransactionIdEvenWhenNoPatientWasFound(string errorCode)
        {
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheTransactionId(actualResponse, discoveryRequest);
        }

        [Theory]
        [InlineData(ErrorCode.NoPatientFound, HttpStatusCode.NotFound,
            "No Matching Record Found or More than one Record Found")]
        [InlineData(ErrorCode.MultiplePatientsFound, HttpStatusCode.NotFound,
            "No Matching Record Found or More than one Record Found")]
        public async void ShouldSendRequestStatusWith404WhenNoPatientWasFound(string errorCode,
            HttpStatusCode expectedStatusCode, string expectedResponseDescription)
        {
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheExpectedStatus(actualResponse, discoveryRequest, expectedStatusCode,
                expectedResponseDescription);
        }

        [Theory]
        [InlineData(ErrorCode.NoPatientFound)]
        [InlineData(ErrorCode.MultiplePatientsFound)]
        public async void ShouldSendTheErrorDetailsWhenNoPatientWasFound(string errorCode)
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);
            AndTheUserDoesNotMatchAnyPatientBecauseOf(errorCode, out ErrorRepresentation errorRepresentation);

            //When
            await careContextDiscoveryController.GetPatientCareContext(discoveryRequest, correlationId, requestId);

            //Then
            ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(discoveryRequest,
                out GatewayDiscoveryRepresentation actualResponse);
            AndTheResponseShouldContainTheErrorDetails(actualResponse, errorRepresentation);
        }

        #endregion

        #region Ensure the job will be triggered by the background worker

        [Fact]
        public void ShouldAddTheDiscoveryTaskToTheBackgroundJobList()
        {
            var correlationId = Uuid.Generate().ToString();
            var requestId = Uuid.Generate().ToString();
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            //Given
            GivenAPatientStartedANewDiscoveryRequest(JohnDoe, out DiscoveryRequest discoveryRequest);

            //When
            careContextDiscoveryController.DiscoverPatientCareContexts(correlationId, requestId, timestamp, discoveryRequest);

            //Then
            backgroundJobs.Should().ContainKey("GetPatientCareContext");
            ((DiscoveryRequest) backgroundJobs["GetPatientCareContext"].Args.First()).Should()
                .BeSameAs(discoveryRequest);
        }

        #endregion


        #region Given

        private static void GivenAPatientStartedANewDiscoveryRequest(User user, out DiscoveryRequest discoveryRequest)
        {
            discoveryRequest = new DiscoveryRequestPayloadBuilder()
                .FromUser(user)
                .WithVerifiedIdentifiers(IdentifierType.ABHA_NUMBER, "12345678910")
                .WithTransactionId("aTransactionId")
                .Build();
        }

        private void AndThisPatientMatchASingleRegisteredPatient(User patient, IEnumerable<string> matchBy,
            out DiscoveryRepresentation discoveryRepresentation)
        {
            var discovery = new DiscoveryRepresentation(
                new PatientEnquiryRepresentation(
                    patient.Id,
                    patient.Name,
                    patient.CareContexts,
                    matchBy
                )
            );

            patientDiscoveryMock
                .Setup(patientDiscovery => patientDiscovery.PatientFor(It.IsAny<DiscoveryRequest>()))
                .Returns(async () => (discovery, null));

            discoveryRepresentation = discovery;
        }

        private void AndTheUserDoesNotMatchAnyPatientBecauseOf(string errorCode,
            out ErrorRepresentation errorRepresentation)
        {
            var error = new ErrorRepresentation(new Error(ErrorCode.NoPatientFound, "unusedMessage"));

            patientDiscoveryMock
                .Setup(patientDiscovery => patientDiscovery.PatientFor(It.IsAny<DiscoveryRequest>()))
                .Returns(async () => (null, error));

            errorRepresentation = new ErrorRepresentation(new Error(ErrorCode.NoPatientFound, "unusedMessage"));
        }

        private void ButTheDataSourceIsNotReachable(out ErrorRepresentation errorRepresentation)
        {
            patientDiscoveryMock
                .Setup(patientDiscovery => patientDiscovery.PatientFor(It.IsAny<DiscoveryRequest>()))
                .Returns(async () => throw new Exception("Exception coming from tests"));

            errorRepresentation =
                new ErrorRepresentation(new Error(ErrorCode.ServerInternalError, "Unreachable external service"));
        }

        #endregion

        #region Then

        private void ThenAResponseToThisTransactionShouldHaveBeenSentToTheGateway(
            DiscoveryRequest discoveryRequest,
            out GatewayDiscoveryRepresentation actualResponse)
        {
            responsesSentToGateway.Should().ContainKey(discoveryRequest.TransactionId);

            actualResponse = responsesSentToGateway[discoveryRequest.TransactionId];
        }

        private static void AndTheSentResponseShouldContainTheFoundPatient(
            GatewayDiscoveryRepresentation actualResponse,
            PatientEnquiryRepresentation patientEnquiry)
        {
            var patientDiscoveryRepresentation = PatientDiscoveryMapper.Map(patientEnquiry);
            actualResponse.Patient.Should().BeEquivalentTo(patientDiscoveryRepresentation);
        }

        private static void AndTheResponseShouldNotContainAnyPatientDetails(
            GatewayDiscoveryRepresentation actualResponse)
        {
            actualResponse.Patient.Should().BeNull();
        }

        private static void AndTheResponseShouldContainTheMatchFields(GatewayDiscoveryRepresentation actualResponse,
            ICollection<string> matchedFields)
        {
            actualResponse.MatchedBy.Count().Should().Be(matchedFields.Count);
            foreach (var matchedFieldName in matchedFields)
            {
                actualResponse.MatchedBy.Should().ContainEquivalentOf(matchedFieldName);
            }
        }

        private static void AndTheResponseShouldNotContainAyMatchFields(GatewayDiscoveryRepresentation actualResponse)
        {
            actualResponse.Patient.Should().BeNull();
        }

        private static void AndTheResponseShouldContainTheTransactionId(GatewayDiscoveryRepresentation actualResponse,
            DiscoveryRequest discoveryRequest)
        {
            actualResponse.TransactionId.Should().Be(discoveryRequest.TransactionId);
        }

        private static void AndTheResponseShouldContainTheErrorDetails(GatewayDiscoveryRepresentation actualResponse,
            ErrorRepresentation errorRepresentation)
        {
            actualResponse.Error.Code.Should().Be(errorRepresentation.Error.Code);
            actualResponse.Error.Message.Should().Be(errorRepresentation.Error.Message);
        }

        private static void AndTheResponseShouldNotContainAnyError(GatewayDiscoveryRepresentation actualResponse)
        {
            actualResponse.Error.Should().BeNull();
        }

        private static void AndTheResponseShouldContainTheExpectedStatus(GatewayDiscoveryRepresentation actualResponse,
            DiscoveryRequest discoveryRequest, HttpStatusCode expectedStatusCode, string expectedMessage)
        {
            //actualResponse.Response.RequestId.Should().Be(discoveryRequest.RequestId);
            // actualResponse.Resp.StatusCode.Should().Be(expectedStatusCode);
            // actualResponse.Resp.Message.Should().Be(expectedMessage);
        }

        #endregion

        #region SetUp

        private static void SetupGatewayClientToSaveAllSentDiscoveryIntoThisList(Mock<IGatewayClient> gatewayClientMock,
            Dictionary<string, GatewayDiscoveryRepresentation> responsesSentToGateway)
        {
            var correlationId = Uuid.Generate().ToString();
            gatewayClientMock
                .Setup(gatewayClient => gatewayClient.SendDataToGateway(
                    It.IsAny<string>(), It.IsAny<GatewayDiscoveryRepresentation>(), It.IsAny<string>(),
                    It.IsAny<string>(),null,null,null)
                )
                .Callback<string, GatewayDiscoveryRepresentation, string, string,string,string,string>(
                    (urlPath, response, cmSuffix, correlationId,hipId,requestId,linkToken) =>
                    {
                        responsesSentToGateway.TryAdd(response.TransactionId, response);
                    });
        }

        private void SetupBackgroundJobClientToSaveAllCreatedJobsIntoThisList(
            Mock<IBackgroundJobClient> backgroundJobClientMock,
            Dictionary<string, Job> backgroundJobs)
        {
            backgroundJobClientMock
                .Setup(s => s.Create(It.IsAny<Job>(), It.IsAny<IState>()))
                .Callback<Job, IState>((job, state) => { backgroundJobs.Add(job.Method.Name, job); });
        }

        #endregion
    }
}