using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Creation.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation
{
    using static Constants;

    [ApiController]
    public class CreationController : Controller
    {
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<CreationController> logger;
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;
        private CreationRepository repository;

        public CreationController(IGatewayClient gatewayClient,
            ILogger<CreationController> logger,
            HttpClient httpClient,
            OpenMrsConfiguration openMrsConfiguration, CreationRepository repository)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.httpClient = httpClient;
            this.openMrsConfiguration = openMrsConfiguration;
            this.repository = repository;
        }

        [Route(AADHAAR_GENERATE_OTP)]
        public async Task<ActionResult> GenerateAadhaarOtp(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] AadhaarOTPGenerationRequest aadhaarOtpGenerationRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return statusCodeResult.Result;
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }
            }

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation,
                    "Request for generate-aadhaar-otp to gateway: {@GatewayResponse}",
                    aadhaarOtpGenerationRequest);
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"correlationId: {{correlationId}}," +
                                        $" aadhaar: {{aadhaar}}",
                     correlationId, aadhaarOtpGenerationRequest.aadhaar);
                string text = await EncryptText(aadhaarOtpGenerationRequest.aadhaar);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,AADHAAR_GENERATE_OTP, new AadhaarOTPGenerationRequest(text), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse =
                            JsonConvert.DeserializeObject<AadhaarOTPGenerationResponse>(responseContent);
                        repository.txnId = generationResponse?.txnId;
                        return Accepted(new AadhaarOTPGenerationResponse(generationResponse?.mobileNumber));
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for " +
                                                               "generate-aadhaar-otp request" + exception.StackTrace);
                
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        [Route(AADHAAR_VERIFY_OTP)]
        public async Task<ActionResult> VerifyAadhaarOtp(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, OTPVerifyRequest otpVerifyRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return statusCodeResult.Result;
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }
            }

            var txnId = repository.txnId;
            try
            {
                string encryptedOTP = await EncryptText(otpVerifyRequest.otp);
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for verify-aadhaar-otp to gateway:  correlationId: {{correlationId}}," +
                                        $"txnId: {{txnId}}",
                     correlationId,txnId);

                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post, AADHAAR_VERIFY_OTP,
                    new OTPVerifyRequest(txnId, encryptedOTP), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var otpResponse = JsonConvert.DeserializeObject<AadhaarOTPVerifyResponse>(responseContent);
                        return Accepted(otpResponse);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for txnId: {txnId} for" +
                                                               " verify-aadhaar-otp", txnId);
                
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }

        [Route(CHECK_GENERATE_MOBILE_OTP)]
        public async Task<ActionResult> CheckAndGenerateMobileOTP(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, MobileOTPGenerationRequest mobileOtpGenerationRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return statusCodeResult.Result;
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }
            }

            var txnId = repository.txnId;
            var mobileNumber = mobileOtpGenerationRequest.mobile;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for generate-mobile-otp to gateway: correlationId: {{correlationId}}," +
                                        $" mobile: {{mobile}}",
                    correlationId,mobileNumber);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post, CHECK_GENERATE_MOBILE_OTP,
                    new MobileOTPGenerationRequest(txnId, mobileNumber), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse = JsonConvert.DeserializeObject<MobileOTPGenerationResponse>(responseContent);
                        repository.txnId = generationResponse?.txnId;
                        return Accepted(new MobileOTPGenerationResponse(generationResponse?.mobileLinked));
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                    
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for txnId: {txnId} for" +
                                                               " generate-mobile-otp", txnId);
                
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(VERIFY_MOBILE_OTP)]
        public async Task<ActionResult> VerifyMobileOTP(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, OTPVerifyRequest otpVerifyRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return statusCodeResult.Result;
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }
            }

            var txnId = repository.txnId;
            try
            {
                string encryptedOTP = await EncryptText(otpVerifyRequest.otp);
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for verify-mobile-otp to gateway:  correlationId: {{correlationId}}," +
                                        $"txnId: {{txnId}}",
                    correlationId,txnId);

                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post, VERIFY_MOBILE_OTP,
                    new OTPVerifyRequest(txnId, encryptedOTP), correlationId))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        var otpResponse = JsonConvert.DeserializeObject<TransactionResponse>(responseContent);
                        repository.txnId = otpResponse?.txnId;
                        return Accepted();
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for txnId: {txnId} for" +
                                                               " verify-mobile-otp", txnId);
                
            }
           
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(Constants.CREATE_ABHA_ID)]
        public async Task<ActionResult> CreateABHAId(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,CreateABHARequest createAbhaRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return statusCodeResult.Result;
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized);
                }
            }
        
            var txnId = repository.txnId;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for create-ABHA to gateway:  correlationId: {{correlationId}}," +
                                        $"txnId: {{txnId}}",
                    correlationId,txnId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post, CREATE_ABHA_ID,
                    new CreateABHARequest(createAbhaRequest.healthId,txnId), correlationId))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        var createAbhaResponse = JsonConvert.DeserializeObject<CreateABHAResponse>(responseContent);
                        return Accepted(createAbhaResponse);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for txnId: {txnId} for" +
                                                               " create-ABHA", txnId);
                
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(GET_ABHA_CARD)]
        public async Task<Tuple<ActionResult,Stream>> getPngCard(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, ABHACardRequest abhaCardRequest)
        {
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    string sessionId = Request.Cookies[REPORTING_SESSION];
            
                    Task<StatusCodeResult> statusCodeResult = IsAuthorised(sessionId);
                    if (!statusCodeResult.Result.StatusCode.Equals(StatusCodes.Status200OK))
                    {
                        return  new Tuple<ActionResult, Stream>(statusCodeResult.Result, null);
                    }
                }
                else
                {
                    return new Tuple<ActionResult, Stream>(StatusCode(StatusCodes.Status401Unauthorized), null);
                       
                }
            }
            
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for abha-card to gateway:  correlationId: {{correlationId}}",
                    correlationId);

                var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get, GET_ABHA_CARD,
                    null, correlationId, $"{abhaCardRequest.tokenType} {abhaCardRequest.token}");
                var stream = await response.Content.ReadAsStreamAsync();
                return new Tuple<ActionResult, Stream>(StatusCode(StatusCodes.Status202Accepted),stream);
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for Abha-card generation");
                
            }
            return new Tuple<ActionResult, Stream>(StatusCode(StatusCodes.Status500InternalServerError), null);;
        }
        
        [NonAction]
        private async Task<StatusCodeResult> IsAuthorised(String sessionId)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, openMrsConfiguration.Url + WHO_AM_I);
            request.Headers.Add("Cookie", OPENMRS_SESSION_ID_COOKIE_NAME + "=" + sessionId);

            var response = await httpClient.SendAsync(request).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return StatusCode(StatusCodes.Status401Unauthorized);
            }

            return StatusCode(StatusCodes.Status200OK);
        }
        
        private async Task<string> EncryptText(string text)
        {
            var rsaPublicKey = RSA.Create();
            if (repository.public_key == null)
            {
                HttpResponseMessage response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,CERT, null,null);
                repository.public_key = await response.Content.ReadAsStringAsync();
            }
            byte[] byteData = Encoding.UTF8.GetBytes(text);
            rsaPublicKey.ImportFromPem(repository.public_key);
            byte[] bytesEncrypted = rsaPublicKey.Encrypt(byteData, RSAEncryptionPadding.Pkcs1);
            return await Task.FromResult(Convert.ToBase64String(bytesEncrypted));
        }
        
    }
}