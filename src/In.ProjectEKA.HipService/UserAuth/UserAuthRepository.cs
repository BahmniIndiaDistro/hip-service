using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.UserAuth.Database;
using Microsoft.EntityFrameworkCore;
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

        public async Task<Option<AuthConfirm>> Get(string healthId)
        {
            var authConfirm = await authContext.AuthConfirm
                .FirstOrDefaultAsync(c =>
                    c.HealthId == healthId).ConfigureAwait(false);
            if (authConfirm != null)
                authContext.Entry<AuthConfirm>(authConfirm).State = EntityState.Detached;
            return Option.Some<AuthConfirm>(authConfirm);
        }

        public async Task<Option<AuthConfirm>> Add(AuthConfirm authConfirm)
        {
            try
            {
                await authContext.AuthConfirm.AddAsync(authConfirm).ConfigureAwait(false);
                await authContext.SaveChangesAsync();
                authContext.Entry<AuthConfirm>(authConfirm).State = EntityState.Detached;
                return Option.Some(authConfirm);
            }
            catch (Exception e)
            {
                Log.Fatal(e, e.StackTrace);
                return Option.None<AuthConfirm>();
            }
        }

        public bool Update(AuthConfirm authConfirm)
        {
            try
            {
                authContext.AuthConfirm.Update(authConfirm);
                authContext.SaveChanges();
                return true;
            }
            catch (Exception e)
            {
                Log.Fatal(e, e.StackTrace);
                return false;
            }
        }
    }
}