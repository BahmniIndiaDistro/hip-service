using System.ComponentModel.DataAnnotations;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class AuthConfirm
    {
        public string AccessToken { get; }
        [Key] public string HealthId { get; }

        public AuthConfirm(
            string healthId,
            string accessToken
        )
        {
            HealthId = healthId;
            AccessToken = accessToken;
        }
    }
}