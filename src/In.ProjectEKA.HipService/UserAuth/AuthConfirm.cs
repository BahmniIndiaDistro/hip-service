using System.ComponentModel.DataAnnotations;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class AuthConfirm
    {
        public string AccessToken { get; set; }
        public string HealthId { get; set; }
        [Key] public string TransactionId { get; set; }

        public AuthConfirm(
            string healthId,
            string transactionId,
            string accessToken
        )
        {
            HealthId = healthId;
            TransactionId = transactionId;
            AccessToken = accessToken;
        }
    }
}