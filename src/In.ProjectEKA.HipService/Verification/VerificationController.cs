using System;
using System.Net.Http;
using System.Threading.Tasks;
using Hangfire;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Creation;
using In.ProjectEKA.HipService.Creation.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using In.ProjectEKA.HipService.Verification.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static In.ProjectEKA.HipService.Creation.CreationMap;

namespace In.ProjectEKA.HipService.Verification
{
    using static Constants;
    
    [ApiController]
    [Authorize(AuthenticationSchemes = BAHMNI_AUTH)]
    public class VerificationController : Controller
    {
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<VerificationController> logger;
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;
        private readonly GatewayConfiguration gatewayConfiguration;
        private readonly IAbhaService abhaService;
        public static string public_key;

        public VerificationController(IGatewayClient gatewayClient,
            ILogger<VerificationController> logger,
            HttpClient httpClient,
            OpenMrsConfiguration openMrsConfiguration, GatewayConfiguration gatewayConfiguration, IAbhaService abhaService)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.httpClient = httpClient;
            this.openMrsConfiguration = openMrsConfiguration;
            this.gatewayConfiguration = gatewayConfiguration;
            this.abhaService = abhaService;
        }

        [Route(SEARCH_HEALTHID)]
        public async Task<ActionResult> SearchHealthId(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] SearchHealthIdRequest searchHealthIdRequest)
        {
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification,
                    "Request for search healthId to gateway: {@GatewayResponse}", searchHealthIdRequest);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"correlationId: {{correlationId}}," +
                                        $" healthId: {{healthId}}",
                     correlationId, searchHealthIdRequest.healthId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, SEARCH_HEALTHID, searchHealthIdRequest, correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var resp = JsonConvert.DeserializeObject<SearchHealthIdResponse>(responseContent);
                        return Accepted(resp);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                               "search healthId request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        
        [Route(AUTH_INIT_VERIFY)]
        public async Task<ActionResult> AuthInit(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] AuthInitRequest authInitRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification,
                    "Request for auth init to gateway: {@GatewayResponse}", authInitRequest);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"correlationId: {{correlationId}}," +
                                            $" healthId: {{healthId}}" + $" authMethod: {{authMethod}}",
                    correlationId, authInitRequest.healthid,authInitRequest.authMethod);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, AUTH_INIT_VERIFY, authInitRequest, correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse =
                            JsonConvert.DeserializeObject<AuthInitResponse>(responseContent);
                        if (TxnDictionary.ContainsKey(sessionId))
                        {
                            TxnDictionary[sessionId] = generationResponse?.txnId;
                        }
                        else
                        {
                            TxnDictionary.Add(sessionId, generationResponse?.txnId);
                        }
                        return Accepted();
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                                   "auth init request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        [Route(CONFIRM_OTP_VERIFY)]
        public async Task<ActionResult> VerifyOTP(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] OtpVerifyRequest otpVerifyRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;
            
            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            try
            {
                string encryptedOTP = await abhaService.EncryptText(public_key,otpVerifyRequest.otp);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"Request for otp verify to gateway:" +
                                        $"txnId: {{txnId}}",txnId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, 
                    otpVerifyRequest.authMethod == AuthMode.MOBILE_OTP ? CONFIRM_WITH_MOBILE_OTP : CONFIRM_WITH_AADHAAR_OTP, 
                    new OTPVerifyRequest(txnId, encryptedOTP), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var otpResponse = JsonConvert.DeserializeObject<TokenRequest>(responseContent);
                        var profile = await abhaService.getABHAProfile(sessionId,new TokenRequest(otpResponse.token));
                        return Accepted(profile);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                                   "otp verify  request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        
        [Route(CREATE_DEFAULT_PHR_ADDRESS)]
        public async Task<ActionResult> CreatePhrAddress(
            [FromHeader(Name = CORRELATION_ID)] string correlationId)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;
            
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification,
                    "Request for create deflault phr address to gateway");
                using (var response = await gatewayClient.CallABHAService<string>(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, CREATE_DEFAULT_PHR_ADDRESS, 
                    null, correlationId,$"{HealthIdNumberTokenDictionary[sessionId].tokenType} {HealthIdNumberTokenDictionary[sessionId].token}"))
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        return Accepted(new ABHAProfile(responseContent));
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                               "create default phr address request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        [Route(CREATE_PHR_ADDRESS)]
        public async Task<ActionResult> UpdatePhrAddress(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromParameter("healthId")] string healthId)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;
            
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"Request to create and update ABHA-Address to gateway: correlationId: {{correlationId}}," +
                                            $" healthId: {{healthId}}",correlationId, healthId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, ABHA_PATIENT_PROFILE,
                    new ABHAProfile(healthId), correlationId, $"{HealthIdNumberTokenDictionary[sessionId].tokenType} {HealthIdNumberTokenDictionary[sessionId].token}"))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        var abhaProfile = JsonConvert.DeserializeObject<ABHAProfile>(responseContent);
                        return Accepted(abhaProfile);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for create ABHA Address");
                
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(MOBILE_GENERATE_OTP)]
        public async Task<ActionResult> GenerateMobileOtp(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] GenerateMobileOtpRequest generateMobileOtpRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification,
                    "Request for generate mobile otp to gateway: {@GatewayResponse}", generateMobileOtpRequest);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"correlationId: {{correlationId}}," +
                                            $" mobile: {{mobile}}",
                    correlationId, generateMobileOtpRequest.mobile);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaNumberServiceUrl, MOBILE_GENERATE_OTP, generateMobileOtpRequest, correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse =
                            JsonConvert.DeserializeObject<TransactionResponse>(responseContent);
                        if (TxnDictionary.ContainsKey(sessionId))
                        {
                            TxnDictionary[sessionId] = generationResponse?.txnId;
                        }
                        else
                        {
                            TxnDictionary.Add(sessionId, generationResponse?.txnId);
                        }
                        return Accepted();
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                                   "generate mobile otp request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }

        [Route(MOBILE_VERIFY_OTP)]
        public async Task<ActionResult> VerifyMobileOtp(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] VerifyMobileOtpRequest verifyMobileOtpRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            try
            {
                string encryptedOTP = await abhaService.EncryptText(public_key, verifyMobileOtpRequest.otp);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"Request for verify mobile otp to gateway:" +
                                            $"txnId: {{txnId}}", txnId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                    gatewayConfiguration.AbhaNumberServiceUrl,
                    MOBILE_VERIFY_OTP,
                    new OTPVerifyRequest(txnId, encryptedOTP), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var otpResponse = JsonConvert.DeserializeObject<VerifyMobileOtpResponse>(responseContent);
                        TxnDictionary[sessionId] = otpResponse?.txnId;
                        if (VerifiedMobileTokenDictionary.ContainsKey(sessionId))
                        {
                            VerifiedMobileTokenDictionary[sessionId] = $"{T_TOKEN_TYPE} {otpResponse?.token}";;
                        }
                        else
                        {
                            VerifiedMobileTokenDictionary.Add(sessionId, $"{T_TOKEN_TYPE} {otpResponse?.token}");
                        }
                        return Accepted(otpResponse.mobileLinkedHid);
                    }

                    return StatusCode((int) response.StatusCode, responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                                   "verify mobile otp request" + exception.StackTrace);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(GET_AUTHORIZED_TOKEN)]
        public async Task<ActionResult> GetAuthorizedToken(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] AuthorizedTokenRequest authorizedTokenRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            var tToken = VerifiedMobileTokenDictionary.ContainsKey(sessionId) ? VerifiedMobileTokenDictionary[sessionId] : null;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"Request for get authorized token to gateway:" +
                                            $"txnId: {{txnId}}", txnId);
                logger.Log(LogLevel.Information,
                    LogEvents.Verification, $"correlationId: {{correlationId}}," +
                                            $" ABHA Number: {{abhaNumber}}",
                    correlationId, authorizedTokenRequest.healthId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post, gatewayConfiguration.AbhaNumberServiceUrl,
                    GET_AUTHORIZED_TOKEN,
                    new AuthorizedTokenRequest(authorizedTokenRequest.healthId, txnId), correlationId, null, tToken))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);
                        var profile = await abhaService.getABHAProfile(sessionId,new TokenRequest(tokenResponse.token));
                        return Accepted(profile);
                    }

                    return StatusCode((int) response.StatusCode, responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Verification, exception, "Error happened for " +
                                                                   "get authorized token request" + exception.StackTrace);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}