using System;
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
using static In.ProjectEKA.HipService.Creation.CreationMap;

namespace In.ProjectEKA.HipService.Creation
{
    using static Constants;
    
    [ApiController]
    public class LinkController : Controller
    {
        
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<CreationController> logger;
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;
        private readonly GatewayConfiguration gatewayConfiguration;
        public static string public_key;

        public LinkController(IGatewayClient gatewayClient,
            ILogger<CreationController> logger,
            HttpClient httpClient,
            OpenMrsConfiguration openMrsConfiguration, GatewayConfiguration gatewayConfiguration)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.httpClient = httpClient;
            this.openMrsConfiguration = openMrsConfiguration;
            this.gatewayConfiguration = gatewayConfiguration;
        }

        [Route(MOBILE_EMAIL_INIT)]
        public async Task<ActionResult> MobileEmailPhrSearchInit(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] MobileEmailPhrSearchInitRequest phrSearchInitRequest)
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
                    LogEvents.LinkingPhr,
                    "Search for phr-address to gateway: {@GatewayResponse}",
                    phrSearchInitRequest);
                logger.Log(LogLevel.Information,
                    LogEvents.LinkingPhr, $"correlationId: {{correlationId}}," +
                                        $" mobile/email: {{input}}",
                     correlationId, phrSearchInitRequest.input);
                string text = await EncryptText(phrSearchInitRequest.input);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl, 
                    MOBILE_EMAIL_INIT, new MobileEmailPhrSearchInitRequest(text), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse =
                            JsonConvert.DeserializeObject<TransactionInitResponse>(responseContent);
                        if (TxnDictionary.ContainsKey(sessionId))
                        {
                            TxnDictionary[sessionId] = generationResponse?.transactionId;
                        }
                        else
                        {
                            TxnDictionary.Add(sessionId, generationResponse?.transactionId);
                        }
                        return Accepted();
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "phr-address search init" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(MOBILE_EMAIL_PRE_VERIFICATION)]
        public async Task<ActionResult> MobileEmailPhrPreVerify(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] MobileEmailPhrPreVerificationRequest otpVerifyRequest)
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
                logger.Log(LogLevel.Information,
                    LogEvents.LinkingPhr,
                    "Request for phr-address otp pre-verification to gateway: {@GatewayResponse}",
                    otpVerifyRequest);
                string text = await EncryptText(otpVerifyRequest.otp);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl,
                    MOBILE_EMAIL_PRE_VERIFICATION, new MobileEmailPhrPreVerificationRequest(txnId,text), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var verificationResponse =
                            JsonConvert.DeserializeObject<MobileEmailPhrPreVerificationResponse>(responseContent);
                        TxnDictionary[sessionId] = verificationResponse?.transactionId;
                        return Accepted(new MobileEmailPhrPreVerificationResponse(verificationResponse.mobileEmail, verificationResponse.mappedPhrAddress));
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "phr-address pre verification" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(MOBILE_EMAIL_GET_USERTOKEN)]
        public async Task<ActionResult> GetUserTokenForMobileEmailPhr(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] MobileEmailPhrGetUserTokenRequest userTokenRequest)
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
                logger.Log(LogLevel.Information,
                    LogEvents.LinkingPhr,
                    "Request for phr-address user token to gateway: {@GatewayResponse}",
                    userTokenRequest);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl,
                    MOBILE_EMAIL_GET_USERTOKEN, new MobileEmailPhrGetUserTokenRequest(userTokenRequest.phrAddress,txnId), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var tokenResponse =
                            JsonConvert.DeserializeObject<MobileEmailPhrGetUserTokenResponse>(responseContent);
                        if (HealthIdTokenDictionary.ContainsKey(sessionId))
                        {
                            HealthIdTokenDictionary[sessionId] = $"{X_TOKEN_TYPE} {tokenResponse?.token}";
                        }
                        else
                        {
                            HealthIdTokenDictionary.Add(sessionId, $"{X_TOKEN_TYPE} {tokenResponse?.token}");
                        }
                        var healthIdNumber = await getABHAAddressProfile(new TokenRequest(tokenResponse?.token));
                        return Accepted(healthIdNumber);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "phr-address user token to gateway" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(LINK_PHR_ADDRESS)]
        public async Task<ActionResult> LinkABHAAddress(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] PhrAddressLinkRequest phrAddressLinkRequest)
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
                logger.Log(LogLevel.Information,
                    LogEvents.LinkingPhr,
                    "Request for link phr-address to gateway: {@GatewayResponse}",
                    phrAddressLinkRequest);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl,
                    LINK_PHR_ADDRESS, new PhrAddressLinkRequest(phrAddressLinkRequest.action,txnId), correlationId, HealthIdTokenDictionary[sessionId]))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var linkResponse =
                            JsonConvert.DeserializeObject<PhrAddressLinkResponse>(responseContent);
                        return Accepted(linkResponse);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "link phr-address to gateway" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(AUTH_MODE_FOR_HEALTH_ID)]
        public async Task<ActionResult> GetAuthModeForHealthId(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromBody] HealthIdNumberRequest idNumberRequest)
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
                    LogEvents.LinkingPhr,
                    "Request for health id auth-modes to gateway: {@GatewayResponse}",
                    idNumberRequest);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl,
                    AUTH_MODE_FOR_HEALTH_ID, new HealthIdNumberRequest(idNumberRequest.healhtIdNumber), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var authModeResponse =
                            JsonConvert.DeserializeObject<HealthIdAuthModeResponse>(responseContent);
                        if (HealthIdNumberDictionary.ContainsKey(sessionId))
                        {
                            HealthIdNumberDictionary[sessionId] = authModeResponse?.healthIdNumber;
                        }
                        else
                        {
                            HealthIdNumberDictionary.Add(sessionId, authModeResponse?.healthIdNumber);
                        }
                        return Accepted(authModeResponse);
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "health id auth-modes to gateway" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(TRANSACTION_INIT)]
        public async Task<ActionResult> GetAuthModeForHealthId(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromQuery(Name = "authMode")] string authMode)
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
                    LogEvents.LinkingPhr,
                    "Request for health id transaction to gateway with auth-mode: {@GatewayResponse}", authMode);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,gatewayConfiguration.AbhaAddressServiceUrl,
                    TRANSACTION_INIT, new HealthIdNumberRequest(authMode,HealthIdNumberDictionary[sessionId]), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        var txnResponse =
                            JsonConvert.DeserializeObject<TransactionInitResponse>(responseContent);
                        TxnDictionary[sessionId] = txnResponse.transactionId;
                        return Accepted();
                    }
                    return StatusCode((int)response.StatusCode,responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.LinkingPhr, exception, "Error happened for " +
                                                               "health id auth-modes to gateway" + exception.StackTrace);
            }
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
        
        [Route(CHECK_ABHA_ADDRESS)]
        public async Task<string> checkIfABHAAddressExists(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, [FromQuery(Name = "phrAddress")]  string phrAddress)
        {
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, "Request for ABHA-Address Exists to gateway");
                using (var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get, gatewayConfiguration.AbhaAddressServiceUrl,CHECK_ABHA_ADDRESS + "?phrAddress=" + phrAddress,
                    null, null))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        return responseContent;
                    }
                    logger.LogError(LogEvents.Creation, "Error happened for check ABHA Address Exists with error response" + responseContent);
                    return null;
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for check ABHA Address Exists with error response");
                
            }
            return null;
        }
        
        private async Task<ABHAAddressProfile> getABHAAddressProfile(TokenRequest tokenRequest)
        {
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, "Request for ABHA-Addres patient-profile to gateway");
                using (var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get, gatewayConfiguration.AbhaAddressServiceUrl,ABHA_ADDRESS_PROFILE,
                    null, null,$"{tokenRequest.tokenType} {tokenRequest.token}" ))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        var profile = JsonConvert.DeserializeObject<ABHAAddressProfile>(responseContent);
                        return profile;
                    }
                    logger.LogError(LogEvents.Creation, "Error happened for ABHA Address patient profile with error response" + responseContent);
                    return null;
                }
                
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for ABHA Address patient profile");
                
            }
            return null;
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
            if (public_key == null)
            {
                HttpResponseMessage response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,gatewayConfiguration.AbhaAddressServiceUrl, PUBLIC_CERT, null,null);
                public_key = await response.Content.ReadAsStringAsync();
            }
            byte[] byteData = Encoding.UTF8.GetBytes(text);
            rsaPublicKey.ImportFromPem(public_key);
            byte[] bytesEncrypted = rsaPublicKey.Encrypt(byteData, RSAEncryptionPadding.Pkcs1);
            return await Task.FromResult(Convert.ToBase64String(bytesEncrypted));
        }
        
    }
}