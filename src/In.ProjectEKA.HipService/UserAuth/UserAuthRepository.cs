using System;
using System.Linq;
using System.Threading.Tasks;
using Hangfire.Dashboard.Resources;
using In.ProjectEKA.HipService.UserAuth.Database;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.EntityFrameworkCore;
using Optional;
using Serilog;

namespace In.ProjectEKA.HipService.UserAuth
{
    public class UserAuthRepository : IUserAuthRepository
    {
        private readonly AuthContext authContext;
        private readonly NdhmDemographicsContext ndhmDemographicsContext;

        public UserAuthRepository(AuthContext authContext, NdhmDemographicsContext ndhmDemographicsContext)
        {
            this.authContext = authContext;
            this.ndhmDemographicsContext = ndhmDemographicsContext;
        }

        public async Task<Option<AuthConfirm>> Get(string healthId, string hipId)
        {
            var authConfirm = await authContext.AuthConfirm
                .FirstOrDefaultAsync(c =>
                    c.HealthId == healthId && c.HipId == hipId).ConfigureAwait(false);
            // if (authConfirm == null && !string.IsNullOrEmpty(hipId))
            // {
            //     authConfirm = await authContext.AuthConfirm
            //         .FirstOrDefaultAsync(c =>
            //             c.HealthId == healthId && c.HipId == string.Empty).ConfigureAwait(false);
            // }
            if (authConfirm != null)
                authContext.Entry<AuthConfirm>(authConfirm).State = EntityState.Detached;
            return Option.Some<AuthConfirm>(authConfirm);
        }

        public async Task<Option<NdhmDemographics>> GetDemographics(string healthId)
        {
            var ndhmDemographics = await ndhmDemographicsContext.NdhmDemographics
                .FirstOrDefaultAsync(c =>
                    c.HealthId == healthId).ConfigureAwait(false);
            return Option.Some(ndhmDemographics);
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

        public async Task<Option<NdhmDemographics>> AddDemographics(NdhmDemographics ndhmDemographics)
        {
            try
            {
                var result = await ndhmDemographicsContext.NdhmDemographics
                    .FirstOrDefaultAsync(c =>
                        c.HealthId == ndhmDemographics.HealthId).ConfigureAwait(false);
                if (result != null) return Option.None<NdhmDemographics>();
                await ndhmDemographicsContext.NdhmDemographics.AddAsync(ndhmDemographics).ConfigureAwait(false);
                await ndhmDemographicsContext.SaveChangesAsync();
                ndhmDemographicsContext.Entry(ndhmDemographics).State = EntityState.Detached;
                return Option.Some(ndhmDemographics);

            }
            catch (Exception e)
            {
                Log.Fatal(e, e.StackTrace);
                return Option.None<NdhmDemographics>();
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

        public async Task Delete(string healthId, string hipId = null)
        {
            var query = authContext.AuthConfirm.Where(request => request.HealthId == healthId);
            if (hipId != null)
                query = query.Where(request => request.HipId == hipId);
            var deleteRequests = await query.ToListAsync();
            authContext.RemoveRange(deleteRequests);
            await authContext.SaveChangesAsync();
        }

        public async Task DeleteDemographics(string healthId)
        {
            var deleteRequest = await ndhmDemographicsContext.NdhmDemographics
                .FirstAsync(request =>
                    request.HealthId == healthId);
            ndhmDemographicsContext.Remove(deleteRequest);
            await ndhmDemographicsContext.SaveChangesAsync();
        }

        public async Task<Tuple<string, Exception>> GetAccessToken(
            string healthId, string hipId)
        {
            try
            {
                var authRequest = await authContext.AuthConfirm
                    .FirstOrDefaultAsync(request =>
                        request.HealthId.Equals(healthId) && request.HipId.Equals(hipId));
                // if (authRequest == null && !string.IsNullOrEmpty(hipId))
                // {
                //     authRequest = await authContext.AuthConfirm
                //         .FirstOrDefaultAsync(request =>
                //             request.HealthId.Equals(healthId) && request.HipId.Equals(string.Empty));
                // }
                return new Tuple<string, Exception>(authRequest != null ? authRequest.AccessToken : null, null);
            }
            catch (Exception exception)
            {
                Log.Fatal(exception, exception.StackTrace);
                return new Tuple<string, Exception>(null, exception);
            }
        }
    }
}