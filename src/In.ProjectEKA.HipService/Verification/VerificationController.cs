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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static In.ProjectEKA.HipService.Creation.CreationMap;

namespace In.ProjectEKA.HipService.Verification
{
    using static Constants;
    
    [ApiController]
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
            string sessionId = null;
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    sessionId = Request.Cookies[REPORTING_SESSION];
            
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
                                                                   "search healthId request" + exception.StackTrace);
            }
            
            return StatusCode(StatusCodes.Status500InternalServerError);
            
        }
        
        [Route(CONFIRM_OTP_VERIFY)]
        public async Task<ActionResult> VerifyOTP(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] OtpVerifyRequest otpVerifyRequest)
        {
            string sessionId = null;
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    sessionId = Request.Cookies[REPORTING_SESSION];
            
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
            string sessionId = null;
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    sessionId = Request.Cookies[REPORTING_SESSION];
            
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
            string sessionId = null;
            if (Request != null)
            {
                if (Request.Cookies.ContainsKey(REPORTING_SESSION))
                {
                    sessionId = Request.Cookies[REPORTING_SESSION];
            
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
    }
}