using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Creation.Model;
using In.ProjectEKA.HipService.Gateway;
using In.ProjectEKA.HipService.OpenMrs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static In.ProjectEKA.HipService.Creation.CreationMap;

namespace In.ProjectEKA.HipService.Creation
{
    using static Constants;

    [ApiController]
    [Authorize(AuthenticationSchemes = BAHMNI_AUTH)]
    public class CreationController : Controller
    {
        private readonly IGatewayClient gatewayClient;
        private readonly ILogger<CreationController> logger;
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;
        private readonly GatewayConfiguration gatewayConfiguration;
        private readonly IAbhaService abhaService;
        private static string publicKey;

        public CreationController(IGatewayClient gatewayClient,
            ILogger<CreationController> logger,
            HttpClient httpClient,
            OpenMrsConfiguration openMrsConfiguration, GatewayConfiguration gatewayConfiguration,
            IAbhaService abhaService)
        {
            this.gatewayClient = gatewayClient;
            this.logger = logger;
            this.httpClient = httpClient;
            this.openMrsConfiguration = openMrsConfiguration;
            this.gatewayConfiguration = gatewayConfiguration;
            this.abhaService = abhaService;
            if (publicKey == null)
            {
                publicKey = FetchPublicKey().GetAwaiter().GetResult();
            }
        }

        [HttpPost]
        [Route(APP_PATH_GENERATE_AADHAAR_OTP)]
        public async Task<ActionResult> GenerateAadhaarOtp(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            [FromBody] AadhaarOTPGenerationRequest aadhaarOtpGenerationRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

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
                string encryptedAadhaar =
                    await abhaService.EncryptText(GetPublicKey(), aadhaarOtpGenerationRequest.aadhaar);
                ABHAEnrollmentOTPRequest abhaEnrollmentOtpRequest = new ABHAEnrollmentOTPRequest("",
                    new List<ABHAEnrollmentScope>() { ABHAEnrollmentScope.ABHA_ENROL }, ABHAEnrollmentLoginHint.AADHAAR,
                    encryptedAadhaar, OTPSystem.AADHAAR);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, ENROLLMENT_REQUEST_OTP, abhaEnrollmentOtpRequest,
                           correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        AadhaarOTPGenerationResponse generationResponse =
                            JsonConvert.DeserializeObject<AadhaarOTPGenerationResponse>(responseContent);
                        if (TxnDictionary.ContainsKey(sessionId))
                        {
                            TxnDictionary[sessionId] = generationResponse?.txnId;
                        }
                        else
                        {
                            TxnDictionary.Add(sessionId, generationResponse?.txnId);
                        }

                        return Accepted(new AadhaarOTPGenerationResponse(generationResponse?.message));
                    }

                    return StatusCode((int)response.StatusCode, responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for " +
                                                               "generate-aadhaar-otp request" + exception.StackTrace);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        [HttpPost]
        [Route(APP_PATH_VERIFY_OTP_AND_CREATE_ABHA)]
        public async Task<ActionResult> VerifyAadhaarOtpAndCreateABHA(
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            AppVerifyAadhaarOTPRequest appVerifyAadhaarOtpRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            try
            {
                string encryptedOTP =
                    await abhaService.EncryptText(GetPublicKey(), appVerifyAadhaarOtpRequest.otp);
                string mobile = appVerifyAadhaarOtpRequest.mobile;
                logger.Log(LogLevel.Information,
                    LogEvents.Creation,
                    $"Request for verify-aadhaar-otp to gateway:  correlationId: {{correlationId}}," +
                    $"txnId: {{txnId}}",
                    correlationId, txnId);

                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, ENROLLMENT_BY_AADHAAR,
                           new ABHAEnrollByAadhaarRequest(txnId, encryptedOTP, mobile), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (response.IsSuccessStatusCode)
                    {
                        EnrollByAadhaarResponse enrollByAadhaarResponse =
                            JsonConvert.DeserializeObject<EnrollByAadhaarResponse>(responseContent);
                        return Ok(new AadhaarOTPVerifyAndCreateABHAResponse(enrollByAadhaarResponse.Message,
                            enrollByAadhaarResponse.ABHAProfile, enrollByAadhaarResponse.IsNew));
                    }

                    return StatusCode((int)response.StatusCode, responseContent);
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
            [FromHeader(Name = CORRELATION_ID)] string correlationId,
            MobileOTPGenerationRequest mobileOtpGenerationRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            var mobileNumber = mobileOtpGenerationRequest.mobile;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation,
                    $"Request for generate-mobile-otp to gateway: correlationId: {{correlationId}}," +
                    $" mobile: {{mobile}}",
                    correlationId, mobileNumber);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, CHECK_GENERATE_MOBILE_OTP,
                           new MobileOTPGenerationRequest(txnId, mobileNumber), correlationId))
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        var generationResponse =
                            JsonConvert.DeserializeObject<MobileOTPGenerationResponse>(responseContent);
                        TxnDictionary[sessionId] = generationResponse?.txnId;
                        return Accepted(new MobileOTPGenerationResponse(generationResponse?.mobileLinked));
                    }

                    return StatusCode((int)response.StatusCode, responseContent);
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
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            try
            {
                string encryptedOTP = await abhaService.EncryptText(GetPublicKey(), otpVerifyRequest.otp);
                logger.Log(LogLevel.Information,
                    LogEvents.Creation,
                    $"Request for verify-mobile-otp to gateway:  correlationId: {{correlationId}}," +
                    $"txnId: {{txnId}}",
                    correlationId, txnId);

                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, VERIFY_MOBILE_OTP,
                           new OTPVerifyRequest(txnId, encryptedOTP), correlationId))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();
                    if (response.IsSuccessStatusCode)
                    {
                        var otpResponse = JsonConvert.DeserializeObject<TransactionResponse>(responseContent);
                        TxnDictionary[sessionId] = otpResponse?.txnId;
                        return Accepted();
                    }

                    return StatusCode((int)response.StatusCode, responseContent);
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
            [FromHeader(Name = CORRELATION_ID)] string correlationId)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            var txnId = TxnDictionary.ContainsKey(sessionId) ? TxnDictionary[sessionId] : null;
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for create-ABHA to gateway:  correlationId: {{correlationId}}," +
                                        $"txnId: {{txnId}}",
                    correlationId, txnId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, CREATE_ABHA_ID,
                           new CreateABHARequest(txnId), correlationId))
                {
                    var responseContent = await response?.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        var createAbhaResponse = JsonConvert.DeserializeObject<CreateABHAResponse>(responseContent);
                        var tokenRequest = new TokenRequest(createAbhaResponse.token);
                        if (HealthIdNumberTokenDictionary.ContainsKey(sessionId))
                        {
                            HealthIdNumberTokenDictionary[sessionId] = tokenRequest;
                        }
                        else
                        {
                            HealthIdNumberTokenDictionary.Add(sessionId, tokenRequest);
                        }

                        return Accepted(createAbhaResponse);
                    }

                    return StatusCode((int)response.StatusCode, responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for txnId: {txnId} for" +
                                                               " create-ABHA", txnId);
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        [Route(Constants.CREATE_PHR)]
        public async Task<ActionResult> CreateABHAAddress(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, CreateABHAAddressRequest createAbhaRequest)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation,
                    $"Request for create ABHA-Address to gateway:  correlationId: {{correlationId}}",
                    correlationId);
                using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                           gatewayConfiguration.AbhaNumberServiceUrl, CREATE_PHR,
                           createAbhaRequest, correlationId,
                           $"{HealthIdNumberTokenDictionary[sessionId].tokenType} {HealthIdNumberTokenDictionary[sessionId].token}"))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        return Accepted();
                    }

                    var responseContent = await response?.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, responseContent);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for create ABHA Address");
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        [Route(GET_ABHA_CARD)]
        public async Task<IActionResult> getPngCard(
            [FromHeader(Name = CORRELATION_ID)] string correlationId)
        {
            string sessionId = HttpContext.Items[SESSION_ID] as string;

            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for abha-card to gateway:  correlationId: {{correlationId}}",
                    correlationId);

                var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,
                    gatewayConfiguration.AbhaNumberServiceUrl, GET_ABHA_CARD,
                    null, correlationId,
                    $"{HealthIdNumberTokenDictionary[sessionId].tokenType} {HealthIdNumberTokenDictionary[sessionId].token}");
                var stream = await response.Content.ReadAsStreamAsync();
                return File(stream, "image/png");
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception, "Error happened for Abha-card generation");
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        [Route(CREATE_ABHA_ID_BY_AADHAAR_DEMO)]
        public async Task<IActionResult> createAbhaIdByDemographics(
            [FromHeader(Name = CORRELATION_ID)] string correlationId, AadhaarDemoAuthRequest demoAuthRequest)
        {
            try
            {
                logger.Log(LogLevel.Information,
                    LogEvents.Creation, $"Request for aadhaar demo auth to gateway:  correlationId: {{correlationId}}",
                    correlationId);

                var createAbhaRequest = await abhaService.GetHidDemoAuthRequest(demoAuthRequest);

                if (createAbhaRequest != null)
                {
                    using (var response = await gatewayClient.CallABHAService(HttpMethod.Post,
                               gatewayConfiguration.AbhaNumberServiceUrl, CREATE_ABHA_ID_BY_AADHAAR_DEMO,
                               createAbhaRequest, correlationId))
                    {
                        var responseContent = await response?.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode)
                        {
                            var createAbhaResponse = JsonConvert.DeserializeObject<ABHAProfile>(responseContent);
                            return Accepted(createAbhaResponse);
                        }

                        return StatusCode((int)response.StatusCode, responseContent);
                    }
                }
            }
            catch (Exception exception)
            {
                logger.LogError(LogEvents.Creation, exception,
                    "Error happened for abha creation using aadhaar demo auth");
            }

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        private async Task<string> FetchPublicKey()
        {
            var response = await gatewayClient.CallABHAService<string>(HttpMethod.Get,
                gatewayConfiguration.AbhaNumberServiceUrl, ABHA_SERVICE_CERT_URL, null, null);
            var responseData = await response.Content.ReadAsStringAsync();
            var jsonDoc = JsonDocument.Parse(responseData);
            return jsonDoc.RootElement.GetProperty("publicKey").GetString();
        }

        private string GetPublicKey()
        {
            var pemKey = $"-----BEGIN PUBLIC KEY-----\n{publicKey}\n-----END PUBLIC KEY-----";
            return pemKey;
        }
    }
}