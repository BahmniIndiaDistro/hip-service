using System;
using System.Collections.Generic;
using System.Net;
using FluentAssertions;
using Hl7.Fhir.Model;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth;
using In.ProjectEKA.HipService.UserAuth.Model;
using In.ProjectEKA.HipServiceTest.Common.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using Serilog;
using Xunit;
using static In.ProjectEKA.HipService.Common.Constants;
using Meta = In.ProjectEKA.HipService.Link.Model.Meta;
using Task = System.Threading.Tasks.Task;

namespace In.ProjectEKA.HipServiceTest.UserAuth
{
    public class UserAuthControllerTest
    {
        private readonly UserAuthController userAuthController;

        private readonly Mock<ILogger<UserAuthController>> logger =
            new Mock<ILogger<UserAuthController>>();

        private readonly Mock<GatewayClient> gatewayClient = new Mock<GatewayClient>(MockBehavior.Strict, null, null);
        private readonly Mock<IUserAuthService> userAuthService = new Mock<IUserAuthService>();

        private readonly BahmniConfiguration bahmniConfiguration = new BahmniConfiguration()
        {
            Id = "Bahmni"
        };

        public UserAuthControllerTest()
        {
            userAuthController = new UserAuthController(gatewayClient.Object,
                logger.Object,
                userAuthService.Object, bahmniConfiguration);
        }

        [Fact]
        private void ShouldFetchPatientsAuthModes()
        {
            var request = new FetchRequest("hina_patel@ncg", KYC_AND_LINK);
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var query = new FetchQuery(request.healthId, KYC_AND_LINK, requester);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var cmSuffix = "ncg";
            var gatewayFetchModesRequestRepresentation =
                new GatewayFetchModesRequestRepresentation(requestId, timeStamp, query, cmSuffix);
            var correlationId = Uuid.Generate().ToString();
            var modes = new List<Mode>
            {
                {Mode.MOBILE_OTP},
                {Mode.AADHAAR_OTP}
            };
            var onFetchAuthModeRequest = new OnFetchAuthModeRequest(requestId, timeStamp,
                new AuthModeFetch("KYC_AND_LINK", modes), null, new Resp(requestId.ToString()));
            var authModes = string.Join(',', onFetchAuthModeRequest.Auth.Modes);
            userAuthService.Setup(a => a.FetchModeResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation>
                    (gatewayFetchModesRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_FETCH_AUTH_MODES,
                            gatewayFetchModesRequestRepresentation, cmSuffix, correlationId))
                .Returns(Task.CompletedTask)
                .Callback<string, GatewayFetchModesRequestRepresentation, string, string>
                ((path, gr, suffix, corId)
                    => userAuthController.SetAuthModes(onFetchAuthModeRequest));

            if (userAuthController.GetAuthModes(correlationId, request).Result is OkObjectResult authMode)
            {
                authMode.StatusCode.Should().Be(StatusCodes.Status200OK);
                authMode.Value.Should().BeEquivalentTo(authModes);
            }
        }

        [Fact]
        private void ShouldNotFetchPatientsAuthModes()
        {
            var request = new FetchRequest("hina_patel@ncg", KYC_AND_LINK);
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var query = new FetchQuery(request.healthId, KYC_AND_LINK, requester);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var cmSuffix = "ncg";
            var gatewayFetchModesRequestRepresentation =
                new GatewayFetchModesRequestRepresentation(requestId, timeStamp, query, cmSuffix);
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.FetchModeResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation>
                    (gatewayFetchModesRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_FETCH_AUTH_MODES,
                            gatewayFetchModesRequestRepresentation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));

            if (userAuthController.GetAuthModes(correlationId, request).Result is ObjectResult authMode)
            {
                Log.Information(authMode.ToString());
                authMode.StatusCode.Should().Be((int) HttpStatusCode.GatewayTimeout);
            }
        }

        [Fact]
        private void ShouldSendAuthInitAndOnAuthInit()
        {
            var request = new AuthInitRequest("hina_patel@ncg", "MOBILE_OTP", KYC_AND_LINK);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var query = new AuthInitQuery(request.healthId, KYC_AND_LINK, request.authMode, requester);
            var requestId = Guid.NewGuid();
            var cmSuffix = "ncg";
            var gatewayAuthInitRequestRepresentation =
                new GatewayAuthInitRequestRepresentation(requestId, timeStamp, query, cmSuffix);
            var correlationId = Uuid.Generate().ToString();
            var transactionId = new Guid().ToString();
            var auth = new Auth(transactionId, new Meta("string", new DateTime()), Mode.MOBILE_OTP);
            var authOnInitRequest =
                new AuthOnInitRequest(requestId, timeStamp, auth, null, new Resp(requestId.ToString()));
            userAuthService.Setup(a => a.AuthInitResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation>
                    (gatewayAuthInitRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_AUTH_INIT,
                            gatewayAuthInitRequestRepresentation, cmSuffix, correlationId))
                .Callback<string, GatewayAuthInitRequestRepresentation, string, string>
                ((path, gr, suffix, corId)
                    => userAuthController.SetTransactionId(authOnInitRequest))
                .Returns(Task.FromResult(""));

            if (userAuthController.GetTransactionId(correlationId, request).Result is OkObjectResult tId)
            {
                tId.StatusCode.Should().Be(StatusCodes.Status200OK);
            }
        }

        [Fact]
        private void ShouldSendAuthInitAndNotOnAuthInit()
        {
            var request = new AuthInitRequest("hina_patel@ncg", "12344", KYC_AND_LINK);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var query = new AuthInitQuery(request.healthId, KYC_AND_LINK, request.authMode, requester);
            var requestId = Guid.NewGuid();
            var cmSuffix = "ncg";
            var gatewayAuthInitRequestRepresentation =
                new GatewayAuthInitRequestRepresentation(requestId, timeStamp, query, cmSuffix);
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.AuthInitResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation>
                    (gatewayAuthInitRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_AUTH_INIT,
                            gatewayAuthInitRequestRepresentation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));

            if (userAuthController.GetTransactionId(correlationId, request).Result is ObjectResult authMode)
            {
                Log.Information(authMode.ToString());
                authMode.StatusCode.Should().Be((int) HttpStatusCode.GatewayTimeout);
            }
        }

        [Fact]
        private void ShouldSendAuthConfirmAndOnAuthConfirm()
        {
            var authConfirmRequest = new AuthConfirmRequest(new Guid().ToString(), "123444");
            AuthConfirmCredential credential = new AuthConfirmCredential(authConfirmRequest.authCode);
            DateTime timeStamp = DateTime.Now.ToUniversalTime();
            var transactionId = TestBuilder.Faker().Random.Hash();
            Guid requestId = Guid.NewGuid();
            var requester = new Requester("1000005", "HIP");
            var validity = new Validity("LINK", requester, new DateTime(), "1");
            var address = new AuthConfirmAddress(It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<string>());
            var identifiers = new List<Identifiers>()
            {
                new Identifiers("MOBILE", "+919800083232")
            };
            var patient = new AuthConfirmPatient("hina_patel@ncg", "Hina Patel", "F", "1998",
                address, identifiers);
            var onAuthConfirm = new OnConfirmAuth("12", validity, patient);
            var onAuthConfirmRequest = new OnAuthConfirmRequest(requestId, timeStamp, onAuthConfirm,
                null, new Resp(requestId.ToString()));
            var cmSuffix = "ncg";
            GatewayAuthConfirmRequestRepresentation gatewayAuthConfirmRequestRepresentation =
                new GatewayAuthConfirmRequestRepresentation(requestId, timeStamp, transactionId, credential, cmSuffix);
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.AuthConfirmResponse(authConfirmRequest))
                .Returns(new Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation>
                    (gatewayAuthConfirmRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_AUTH_CONFIRM,
                            gatewayAuthConfirmRequestRepresentation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""))
                .Callback<string, GatewayAuthConfirmRequestRepresentation, string, string>
                ((path, gr, suffix, corId)
                    => userAuthController.SetAccessToken(onAuthConfirmRequest));

            if (userAuthController.GetAccessToken(correlationId, authConfirmRequest).Result is OkObjectResult
                accessToken)
            {
                accessToken.StatusCode.Should().Be(StatusCodes.Status200OK);
                accessToken.Value.Should().BeEquivalentTo("12");
            }
        }

        [Fact]
        private void ShouldSendAuthConfirmAndNotOnAuthConfirm()
        {
            var authConfirmRequest = new AuthConfirmRequest(new Guid().ToString(), "123444");
            AuthConfirmCredential credential = new AuthConfirmCredential(authConfirmRequest.authCode);
            DateTime timeStamp = DateTime.Now.ToUniversalTime();
            var transactionId = TestBuilder.Faker().Random.Hash();
            Guid requestId = Guid.NewGuid();
            var cmSuffix = "ncg";
            GatewayAuthConfirmRequestRepresentation gatewayAuthConfirmRequestRepresentation =
                new GatewayAuthConfirmRequestRepresentation(requestId, timeStamp, transactionId, credential, cmSuffix);
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.AuthConfirmResponse(authConfirmRequest))
                .Returns(new Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation>
                    (gatewayAuthConfirmRequestRepresentation, null));
            gatewayClient.Setup(
                    client =>
                        client.SendDataToGateway(PATH_AUTH_CONFIRM,
                            gatewayAuthConfirmRequestRepresentation, cmSuffix, correlationId))
                .Returns(Task.FromResult(""));

            if (userAuthController.GetAccessToken(correlationId, authConfirmRequest).Result is ObjectResult authMode)
            {
                Log.Information(authMode.ToString());
                authMode.StatusCode.Should().Be((int) HttpStatusCode.GatewayTimeout);
            }
        }

        [Fact]
        private void ShouldGiveInvalidHealthIdErrorForFetchModes()
        {
            var request = new FetchRequest("invalidHealthId", KYC_AND_LINK);
            var error = new ErrorRepresentation(new Error(ErrorCode.InvalidHealthId, "Invalid HealthId"));
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.FetchModeResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation>
                    (null, error));

            if (userAuthController.GetAuthModes(correlationId, request).Result is ObjectResult authMode)
            {
                Log.Information(authMode.ToString());
                authMode.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
            }
        }

        [Fact]
        private void ShouldGiveInvalidHealthIdErrorForAuthInit()
        {
            var request = new AuthInitRequest("invalidHealthId", "12344", KYC_AND_LINK);
            var error = new ErrorRepresentation(new Error(ErrorCode.InvalidHealthId, "Invalid HealthId"));
            var correlationId = Uuid.Generate().ToString();

            userAuthService.Setup(a => a.AuthInitResponse(request, bahmniConfiguration))
                .Returns(new Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation>
                    (null, error));

            if (userAuthController.GetTransactionId(correlationId, request).Result is ObjectResult authMode)
            {
                Log.Information(authMode.ToString());
                authMode.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
            }
        }
    }
}