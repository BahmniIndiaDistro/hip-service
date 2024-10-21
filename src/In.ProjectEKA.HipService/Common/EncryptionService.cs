using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Gateway;

namespace In.ProjectEKA.HipService.Common
{
    public class EncryptionService
    {
        private static string publicKey;
        private readonly GatewayClient gatewayClient;
        private readonly GatewayConfiguration gatewayConfiguration;

        public EncryptionService(GatewayClient gatewayClient, GatewayConfiguration gatewayConfiguration)
        {
            this.gatewayClient = gatewayClient;
            this.gatewayConfiguration = gatewayConfiguration;
        }

        public async Task InitializePublicKeyForEncryption()
        {
            var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,
                gatewayConfiguration.AbhaNumberServiceUrl, Constants.ABHA_SERVICE_CERT_URL, null, null);
            if (response.IsSuccessStatusCode)
            {
                var responseData = await response.Content.ReadAsStringAsync();
                var jsonDoc = JsonDocument.Parse(responseData);
                var keyText = jsonDoc.RootElement.GetProperty("publicKey").GetString();
                SetPublicKey(keyText);
            }
            else
            {
                throw new Exception("Failed to initialise Public Key for Encryption from " +
                                    Constants.ABHA_SERVICE_CERT_URL);
            }
        }

        private static void SetPublicKey(string key)
        {
            publicKey = $"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----";
        }

        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(publicKey))
            {
                throw new InvalidOperationException("Public key is not set.");
            }

            var rsaPublicKey = RSA.Create();
            byte[] byteData = Encoding.UTF8.GetBytes(plainText);
            rsaPublicKey.ImportFromPem(publicKey);
            byte[] bytesEncrypted = rsaPublicKey.Encrypt(byteData, RSAEncryptionPadding.OaepSHA1);
            return Convert.ToBase64String(bytesEncrypted);
        }
    }
}