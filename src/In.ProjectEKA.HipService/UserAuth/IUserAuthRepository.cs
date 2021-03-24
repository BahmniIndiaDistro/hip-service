using System.Threading.Tasks;
using Optional;

namespace In.ProjectEKA.HipService.UserAuth
{
    public interface IUserAuthRepository
    {
        Task<Option<AuthConfirm>> Add(AuthConfirm authConfirm);
    }
}