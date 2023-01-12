using System;
using System.Net.Http;
using In.ProjectEKA.HipService.Creation.Model;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Gateway;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation
{
    using static Constants;
    
    public class CreationService : ICreationService
    {
        private readonly GatewayClient gatewayClient;
        private Creation creation;

        public CreationService(GatewayClient gatewayClient, Creation creation)
        {
            this.gatewayClient = gatewayClient;
            this.creation = creation;
        }
        
        public string getTransactionId()
        {
            return creation.txnId;
        }
        

        public AadhaarOTPGenerationResponse AadhaarOTPGenerationResponse(string response)
        {
            var generationResponse = JsonConvert.DeserializeObject<AadhaarOTPGenerationResponse>(response);
            creation.txnId = generationResponse.txnId;
            return new AadhaarOTPGenerationResponse(generationResponse.mobileNumber);
        }
        
        public AadhaarOTPVerifyResponse AadhaarOTPVerifyResponse(string response)
        {
            var responseObj = JsonConvert.DeserializeObject<AadhaarOTPVerifyResponse>(response);
            responseObj.jwtResponse = null;
            return responseObj;
        }

        public async Task<string> EncryptText(string text)
        {
            HttpResponseMessage response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,CERT, null,null);
            string key = await response.Content.ReadAsStringAsync();
            byte[] byteData = Encoding.UTF8.GetBytes(text);
            var rsaPublicKey = RSA.Create();
            rsaPublicKey.ImportFromPem(key);
            byte[] bytesEncrypted = rsaPublicKey.Encrypt(byteData, RSAEncryptionPadding.Pkcs1);
            return await Task.FromResult(Convert.ToBase64String(bytesEncrypted));
        }
    }
}