using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.UserAuth.Database;
using Optional;
using Serilog;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class UserAuthRepository : IUserAuthRepository
    {
        private readonly AuthContext authContext;

        public UserAuthRepository(AuthContext authContext)
        {
            this.authContext = authContext;
        }

        public async Task<Option<AuthConfirm>> Add(AuthConfirm authConfirm)
        {
            try
            {
                await authContext.AuthConfirm.AddAsync(authConfirm);
                await authContext.SaveChangesAsync();
                return Option.Some(authConfirm);
            }
            catch (Exception e)
            {
                Log.Fatal(e, e.StackTrace);
                return Option.None<AuthConfirm>();
            }
        }
    }
}