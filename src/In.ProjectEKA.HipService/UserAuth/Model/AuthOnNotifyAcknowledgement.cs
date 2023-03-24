using In.ProjectEKA.HipService.Gateway.Model;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class AuthOnNotifyAcknowledgement
    {
        public  AuthOnNotifyAcknowledgement(AuthOnNotifyStatus status)
        {
            Status = status;
        }

        public AuthOnNotifyStatus Status { get; }
    }
}