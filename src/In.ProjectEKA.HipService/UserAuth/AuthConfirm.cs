using System.ComponentModel.DataAnnotations;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class AuthConfirm
    {
        public string HealthId { get; }
        public string HipId { get; }
        public string AccessToken { get; }

        public AuthConfirm(
            string healthId,
            string hipId,
            string accessToken
        )
        {
            HealthId = healthId;
            HipId = hipId;
            AccessToken = accessToken;
        }
    }
}