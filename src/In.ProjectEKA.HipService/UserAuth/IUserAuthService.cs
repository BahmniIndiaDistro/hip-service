using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.UserAuth.Model;

namespace In.ProjectEKA.HipService.UserAuth
{
    public interface IUserAuthService
    {
        public Tuple<GatewayFetchModesRequestRepresentation, ErrorRepresentation> FetchModeResponse(
            FetchRequest fetchRequest, BahmniConfiguration bahmniConfiguration);

        public Tuple<GatewayAuthInitRequestRepresentation, ErrorRepresentation> AuthInitResponse(
            AuthInitRequest authInitRequest, BahmniConfiguration bahmniConfiguration);

        public Tuple<GatewayAuthConfirmRequestRepresentation, ErrorRepresentation> AuthConfirmResponse(
            AuthConfirmRequest authConfirmRequest);

        public Task<Tuple<AuthConfirm, ErrorRepresentation>> OnAuthConfirmResponse(
            OnAuthConfirmRequest onAuthConfirmRequest);
    }
}