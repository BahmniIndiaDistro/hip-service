using System.Threading.Tasks;
using Optional;

namespace In.ProjectEKA.HipService.UserAuth
{
    public interface IUserAuthRepository
    {
        Task<Option<AuthConfirm>> Add(AuthConfirm authConfirm);
        Task<Option<AuthConfirm>> Get(string healthId);
        bool Update(AuthConfirm authConfirm);
    }
}