using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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

        public AbhaService(IGatewayClient gatewayClient,
            ILogger<AbhaService> logger,
            GatewayConfiguration gatewayConfiguration)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.gatewayConfiguration = gatewayConfiguration;
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

        public async Task<string> EncryptText(string public_key,string text)
        {
            var rsaPublicKey = RSA.Create();
            if (public_key == null)
            {
                HttpResponseMessage response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,gatewayConfiguration.AbhaNumberServiceUrl,CERT, null,null);
                public_key = await response.Content.ReadAsStringAsync();
            }
            byte[] byteData = Encoding.UTF8.GetBytes(text);
            rsaPublicKey.ImportFromPem(public_key);
            byte[] bytesEncrypted = rsaPublicKey.Encrypt(byteData, RSAEncryptionPadding.Pkcs1);
            return await Task.FromResult(Convert.ToBase64String(bytesEncrypted));
        }
    }
}