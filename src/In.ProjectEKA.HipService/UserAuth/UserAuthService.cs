using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using static In.ProjectEKA.HipService.Common.Constants;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class UserAuthService : IUserAuthService
    {
        private readonly IUserAuthRepository userAuthRepository;

        public UserAuthService(IUserAuthRepository userAuthRepository)
        {
            this.userAuthRepository = userAuthRepository;
        }

        public Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation> FetchModeResponse(
            FetchRequest fetchRequest, BahmniConfiguration bahmniConfiguration)
        {
            var healthId = fetchRequest.healthId;
            if (!IsValidHealthId(healthId))
                return new Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation>
                    (null, new ErrorRepresentation(new Error(ErrorCode.InvalidHealthId, "HealthId is invalid")));
            var patientIdSplit = healthId.Split("@");
            var cmSuffix = patientIdSplit[1];
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var purpose = fetchRequest.purpose;
            var query = purpose != null
                ? new FetchQuery(healthId, purpose, requester)
                : new FetchQuery(healthId, requester);
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            return new Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation>
                (new GatewayFetchModesRequestRepresentation(requestId, timeStamp, query, cmSuffix), null);
        }

        public Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation> AuthInitResponse(
            AuthInitRequest authInitRequest, BahmniConfiguration bahmniConfiguration)
        {
            var healthId = authInitRequest.healthId;
            if (!IsValidHealthId(healthId))
                return new Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation>
                    (null, new ErrorRepresentation(new Error(ErrorCode.InvalidHealthId, "HealthId is invalid")));
            var patientIdSplit = healthId.Split("@");
            var cmSuffix = patientIdSplit[1];
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            var requester = new Requester(bahmniConfiguration.Id, HIP);
            var purpose = authInitRequest.purpose;
            var authInitQuery = purpose != null
                ? new AuthInitQuery(healthId, purpose, authInitRequest.authMode, requester)
                : new AuthInitQuery(healthId, authInitRequest.authMode, requester);
            return new Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation>
                (new GatewayAuthInitRequestRepresentation(requestId, timeStamp, authInitQuery, cmSuffix), null);
        }

        public Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation> AuthConfirmResponse(
            AuthConfirmRequest authConfirmRequest)
        {
            var healthId = authConfirmRequest.healthId;
            if (!IsValidHealthId(healthId))
                return new Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation>
                    (null, new ErrorRepresentation(new Error(ErrorCode.InvalidHealthId, "HealthId is invalid")));
            var patientIdSplit = healthId.Split("@");
            var cmSuffix = patientIdSplit[1];
            var credential = new AuthConfirmCredential(authConfirmRequest.authCode);
            var transactionId = UserAuthMap.HealthIdToTransactionId[healthId];
            var timeStamp = DateTime.Now.ToUniversalTime();
            var requestId = Guid.NewGuid();
            return new Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation>
            (new GatewayAuthConfirmRequestRepresentation(requestId, timeStamp, transactionId, credential, cmSuffix),
                null);
        }

        private static bool IsValidHealthId(string healthId)
        {
            string pattern = @"\w+\S\w+@\w+";
            return Regex.Match(healthId, pattern).Success;
        }

        public async Task<Tuple<AuthConfirm, ErrorRepresentation>> OnAuthConfirmResponse(
            OnAuthConfirmRequest onAuthConfirmRequest)
        {
            var accessToken = onAuthConfirmRequest.auth.accessToken;
            var healthId = onAuthConfirmRequest.auth.patient.id;
            var authConfirm = new AuthConfirm(healthId, UserAuthMap.HealthIdToTransactionId[healthId], accessToken);
            var authConfirmResponse = await userAuthRepository.Add(authConfirm)
                .ConfigureAwait(false);
            if (!authConfirmResponse.HasValue)
            {
                return new Tuple<AuthConfirm, ErrorRepresentation>(null,
                    new ErrorRepresentation(new Error(ErrorCode.DuplicateAuthConfirmRequest,
                        "Auth confirm request already exists")));
            }

            UserAuthMap.HealthIdToTransactionId.Remove(healthId);
            UserAuthMap.RequestIdToAccessToken.Add(Guid.Parse(onAuthConfirmRequest.resp.RequestId), accessToken);
            return new Tuple<AuthConfirm, ErrorRepresentation>(authConfirm, null);
        }
    }
}