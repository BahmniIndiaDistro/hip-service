using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Creation.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static In.ProjectEKA.HipService.Creation.CreationMap;

namespace In.ProjectEKA.HipService.Creation
{
    using static Constants;
    public class AbhaService : IAbhaService
    {
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<AbhaService> logger;
        private readonly GatewayConfiguration gatewayConfiguration;
        private readonly IOpenMrsClient openMrsClient;

        public AbhaService(IGatewayClient gatewayClient,
            ILogger<AbhaService> logger,
            GatewayConfiguration gatewayConfiguration, IOpenMrsClient openMrsClient)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.gatewayConfiguration = gatewayConfiguration;
            this.openMrsClient = openMrsClient;
        }
        
        
        public async Task<ABHAProfile> getABHAProfile(string sessionId, TokenRequest tokenRequest)
        {
            
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, "Request for ABHA-patient-profile to gateway");
                if (HealthIdNumberTokenDictionary.ContainsKey(sessionId))
                {
                    HealthIdNumberTokenDictionary[sessionId] = tokenRequest;
                }
                else
                {
                    HealthIdNumberTokenDictionary.Add(sessionId, tokenRequest);
                }
                using (var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get, gatewayConfiguration.AbhaNumberServiceUrl,ABHA_PATIENT_PROFILE,
                    null, null,$"{tokenRequest.tokenType} {tokenRequest.token}" ))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        var createAbhaResponse = JsonConvert.DeserializeObject<ABHAProfile>(responseContent);
                        return createAbhaResponse;
                    }
                    logger.LogError(LogEvents.Creation, "Error happened for ABHA patient profile with error response" + responseContent);
                    return null;
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for ABHA patient profile");
                
            }
            return null;
        }
        public async Task<CreateHIdDemoAuthRequest> GetHidDemoAuthRequest(AadhaarDemoAuthRequest aadhaarDemoAuthRequest)
        {

            var query = HttpUtility.ParseQueryString(string.Empty);
            query["state"] = aadhaarDemoAuthRequest.state;
            query["district"] = aadhaarDemoAuthRequest.district;

            var response = await openMrsClient.GetAsync($"{PATH_OPENMRS_LGD_CODE}?{query}");
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var content = await response.Content.ReadAsStringAsync();
                var jsonDoc = JsonDocument.Parse(content);
                var root = jsonDoc.RootElement;
                
                return new CreateHIdDemoAuthRequest(
                    gatewayConfiguration.BenefitName,
                    aadhaarDemoAuthRequest.aadhaarNumber, aadhaarDemoAuthRequest.name,
                    aadhaarDemoAuthRequest.gender,
                    aadhaarDemoAuthRequest.dateOfBirth, aadhaarDemoAuthRequest.mobileNumber,
                    root.GetProperty("districtCode").ToString(), root.GetProperty("stateCode").ToString());
            }
            return null;
        }
    }
}