using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Creation.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.UserAuth.Model;

namespace In.ProjectEKA.HipService.Creation
{
    public interface IAbhaService
    {
        public Task<ABHAProfile> getABHAProfile(string sessionId, TokenRequest tokenRequest);
        
        Task<CreateHIdDemoAuthRequest> GetHidDemoAuthRequest(AadhaarDemoAuthRequest request);
    }
}