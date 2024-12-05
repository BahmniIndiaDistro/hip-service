namespace In.ProjectEKA.HipService.Common
{
    public static class Constants
    {
        public const string CURRENT_VERSION = "v0.5";
        public const string UPDATED_VERSION = "v1.0";
        public const string VERSION_V1 = "v1";
        public const string VERSION_V2 = "v2";
        public const string VERSION_V3 = "v3";
        
        //APIs Used for ABHA Creation from Frontend
        public const string APP_PATH_GENERATE_AADHAAR_OTP = "/" + VERSION_V3 + "/hip/generateAadhaarOtp";
        public const string APP_PATH_VERIFY_OTP_AND_CREATE_ABHA = "/" + VERSION_V3 + "/hip/verifyOtpAndCreateABHA";
        public const string APP_PATH_GENERATE_MOBILE_OTP = "/" + VERSION_V3 + "/hip/generateMobileOtp";
        public const string APP_PATH_VERIFY_MOBILE_OTP = "/" + VERSION_V3 + "/hip/verifyMobileOtp";
        public const string APP_PATH_GET_ABHA_ADDRESS_SUGGESTIONS = "/" + VERSION_V3 + "/hip/getAbhaAddressSuggestions";
        public const string APP_PATH_CREATE_ABHA_ADDRESS = "/" + VERSION_V3 + "/hip/createAbhaAddress";
        public const string APP_PATH_GET_ABHA_CARD = "/" + VERSION_V3 + "/hip/getAbhaCard";

        public const string APP_PATH_VERIFICATION_REQUEST_OTP = "/" + VERSION_V3 + "/hip/verification/requestOtp";
        public const string APP_PATH_VERIFICATION_VERIFY_OTP = "/" + VERSION_V3 + "/hip/verification/verifyOtp";
        public const string APP_PATH_VERIFICATION_VERIFY_ABHA_ACCOUNT = "/" + VERSION_V3 + "/hip/verification/verifyAbhaAccount";
        public const string APP_PATH_VERIFICATION_ABHA_PROFILE = "/" + VERSION_V3 + "/hip/verification/getAbhaProfile";
        public const string APP_PATH_VERIFICATION_ABHAADDRESS_SEARCH = "/" + VERSION_V3 + "/hip/verification/abhaAddress/search";
        public const string APP_PATH_VERIFICATION_ABHAADDRESS_REQUEST_OTP = "/" + VERSION_V3 + "/hip/verification/abhaAddress/requestOtp";
        public const string APP_PATH_VERIFICATION_ABHAADDRESS_VERIFY_OTP = "/" + VERSION_V3 + "/hip/verification/abhaAddress/verifyOtp";
        public const string APP_PATH_VERIFICATION_ABHAADDRESS_PROFILE = "/" + VERSION_V3 + "/hip/verification/abhaAddress/getProfile";
        public const string APP_PATH_VERIFICATION_ABHAADDRESS_CARD = "/" + VERSION_V3 + "/hip/verification/abhaAddress/getCard";

        public const string PATH_SESSIONS =  "api/hiecm/gateway/"+VERSION_V3+"/sessions";

        public const string PATH_CARE_CONTEXTS_DISCOVER = CURRENT_VERSION + "/care-contexts/discover";
        public const string PATH_CONSENTS_HIP = CURRENT_VERSION + "/consents/hip/notify";
        public const string PATH_LINKS_LINK_INIT = CURRENT_VERSION + "/links/link/init";
        public const string PATH_LINKS_LINK_CONFIRM = CURRENT_VERSION + "/links/link/confirm";
        public const string PATH_HEALTH_INFORMATION_HIP_REQUEST = CURRENT_VERSION + "/health-information/hip/request";
        public const string PATH_HEART_BEAT = CURRENT_VERSION + "/heartbeat";
        public const string PATH_READINESS = CURRENT_VERSION + "/readiness";

        public const string PATH_ON_AUTH_CONFIRM = CURRENT_VERSION + "/users/auth/on-confirm";
        public const string PATH_ON_AUTH_INIT = "/" + CURRENT_VERSION + "/users/auth/on-init";
        public const string PATH_ON_FETCH_AUTH_MODES = "/" + CURRENT_VERSION + "/users/auth/on-fetch-modes";
        public const string PATH_ON_ADD_CONTEXTS = "/" + CURRENT_VERSION + "/links/link/on-add-contexts";
        public const string PATH_ON_NOTIFY_CONTEXTS = "/" + CURRENT_VERSION + "/links/context/on-notify";
        public static readonly string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        public static readonly string PATH_ON_DISCOVER = "/" + CURRENT_VERSION + "/care-contexts/on-discover";
        public static readonly string PATH_ON_LINK_INIT = "/" + CURRENT_VERSION + "/links/link/on-init";
        public static readonly string PATH_ON_LINK_CONFIRM = "/" + CURRENT_VERSION + "/links/link/on-confirm";
        public static readonly string PATH_CONSENT_ON_NOTIFY = "/" + CURRENT_VERSION + "/consents/hip/on-notify";

        public static readonly string PATH_HEALTH_INFORMATION_ON_REQUEST = "/" + CURRENT_VERSION +
                                                                           "/health-information/hip/on-request";

        public static readonly string PATH_HEALTH_INFORMATION_NOTIFY_GATEWAY = "/" + CURRENT_VERSION +
                                                                               "/health-information/notify";

        public static readonly string PATH_AUTH_CONFIRM = "/" + CURRENT_VERSION + "/users/auth/confirm";

        public static readonly string PATH_OPENMRS_FHIR = "ws/fhir2/R4/metadata";
        public static readonly string PATH_OPENMRS_REST = "images/openmrs-favicon.ico";
        public static readonly string PATH_OPENMRS_HITYPE = "ws/rest/v1/hip/";
        public static readonly string CONFIG_KEY = "OpenMrs";
        public static readonly string PATH_OPENMRS_LGD_CODE = "ws/rest/v1/hip/lgdCode";
        public static readonly string PATH_OPENMRS_UPDATE_IDENTIFIER = "ws/rest/v1/hip/existingPatients/update";

        public const string CORRELATION_ID = "CORRELATION-ID";
        public const string PATH_PATIENT_PROFILE_ON_SHARE = "/" + CURRENT_VERSION + "/patients/profile/on-share";
        public const string PATH_FETCH_AUTH_MODES = "/" + CURRENT_VERSION + "/users/auth/fetch-modes";
        public const string PATH_ADD_PATIENT_CONTEXTS = "/" + CURRENT_VERSION + "/links/link/add-contexts";
        public const string PATH_NOTIFY_PATIENT_CONTEXTS = "/" + CURRENT_VERSION + "/links/context/notify";
        public const string PATH_FETCH_MODES = "/" + CURRENT_VERSION + "/hip/fetch-modes";
        public const string PATH_NEW_CARECONTEXT = "/" + CURRENT_VERSION + "/hip/new-carecontext";
        public const string PATH_ADD_CONTEXTS = "/" + CURRENT_VERSION + "/hip/add-contexts";
        public const string PATH_NOTIFY_CONTEXTS = "/" + CURRENT_VERSION + "/hip/notify";
        public const string KYC_AND_LINK = "KYC_AND_LINK";
        public const string HIP = "HIP";
        public const string PATH_AUTH_INIT = "/" + CURRENT_VERSION + "/users/auth/init";
        public const string PATH_HIP_AUTH_INIT = "/" + CURRENT_VERSION + "/hip/auth/init";
        public const string PATH_HIP_AUTH_CONFIRM = "/" + CURRENT_VERSION + "/hip/auth/confirm";
        public const string PATH_ADD_NDHM_DEMOGRAPHICS = "/" + CURRENT_VERSION + "/hip/ndhm-demographics";
        public const string PATH_DEMOGRAPHICS = "/" + CURRENT_VERSION + "/hip/auth/demographics";
        public const string PATH_HIP_DIRECT_AUTH = "/" + CURRENT_VERSION + "/hip/auth/direct";
        public const string PATH_AUTH_NOTIFY = "/" + CURRENT_VERSION + "/users/auth/notify";
        public const string PATH_AUTH_ON_NOTIFY = "/" + CURRENT_VERSION + "/users/auth/on-notify";

        public const string PATH_HIP_SMS_NOTIFY = "/" + CURRENT_VERSION + "/hip/patients/sms/notify";
        public const string PATH_SMS_NOTIFY = "/" + CURRENT_VERSION + "/patients/sms/notify2";
        public const string PATH_SMS_ON_NOTIFY = "/" + CURRENT_VERSION + "/patients/sms/on-notify";

        public const string REPORTING_SESSION = "reporting_session";
        public const string OPENMRS_SESSION_ID_COOKIE_NAME = "JSESSIONID";
        public const string WHO_AM_I = "/ws/rest/v1/bahmnicore/whoami";
        public const string SESSION_ID = "session_id";

        public const string MOBILE = "MOBILE";

        public const string DEEPLINK_URL = "https://link.to.health.records";
        public const string PATH_PATIENT_NOTIFY = "/" + CURRENT_VERSION + "/patients/status/notify";
        public const string PATH_PATIENT_ON_NOTIFY = "/" + CURRENT_VERSION + "/patients/status/on-notify";
        public const string PATH_PROFILE_SHARE = "/api/" + VERSION_V3 + "/hip/patient/share";
        public const string PATH_PROFILE_ON_SHARE = "/api/hiecm/patient-share/"+VERSION_V3 +"/on-share";
        public const string GET_PATIENT_QUEUE = "/" + VERSION_V3 + "/hip/getPatientQueue";

        public const string ABHA_SERVICE_CERT_URL = "/" + VERSION_V3 + "/profile/public/certificate";
        public const string ENROLLMENT_REQUEST_OTP = "/" + VERSION_V3 + "/enrollment/request/otp";
        public const string ENROLLMENT_BY_AADHAAR = "/" + VERSION_V3 + "/enrollment/enrol/byAadhaar";
        public const string ENROLLMENT_AUTH_BY_ABDM = "/" + VERSION_V3 + "/enrollment/auth/byAbdm";
        public const string GET_ABHA_ADDRESS_SUGGESTIONS = "/" + VERSION_V3 + "/enrollment/enrol/suggestion";
        public const string CREATE_ABHA_ADDRESS = "/" + VERSION_V3 + "/enrollment/enrol/abha-address";
        public const string GET_ABHA_CARD =  "/" + VERSION_V3 + "/profile/account/abha-card";
        public const string ABHA_LOGIN_REQUEST_OTP = "/" + VERSION_V3 + "/profile/login/request/otp";
        public const string ABHA_LOGIN_VERIFY_OTP = "/" + VERSION_V3 + "/profile/login/verify";
        public const string VERIFY_ABHA_ACCOUNT = "/" + VERSION_V3 + "/profile/login/verify/user";
        public const string ABHA_ACCOUNT = "/" + VERSION_V3 + "/profile/account";
        public const string ABHA_PATIENT_PROFILE = "/" + VERSION_V2 + "/account/profile";
        public const string SEARCH_ABHA_ADDRESS = "/login/abha/search";
        public const string ABHA_ADDRESS_REQUEST_OTP = "/login/abha/request/otp";
        public const string ABHA_ADDRESS_VERIFY_OTP = "/login/abha/verify";
        public const string ABHA_ADDRESS_GET_PROFILE = "/login/profile/abha-profile";
        public const string ABHA_ADDRESS_GET_CARD = "/login/profile/abha/phr-card";
        public const string AUTH_INIT_VERIFY = "/" + VERSION_V2 + "/auth/init";
        public const string CONFIRM_OTP_VERIFY = "/" + VERSION_V2 + "/hip/confirmOTP";
        public const string CONFIRM_WITH_MOBILE_OTP = "/" + VERSION_V2 + "/auth/confirmWithMobileOTP";
        public const string CONFIRM_WITH_AADHAAR_OTP = "/" + VERSION_V2 + "/auth/confirmWithAadhaarOtp";
        public const string MOBILE_GENERATE_OTP = "/" + VERSION_V2 + "/registration/mobile/login/generateOtp";
        public const string MOBILE_VERIFY_OTP = "/" + VERSION_V2 + "/registration/mobile/login/verifyOtp";
        public const string GET_AUTHORIZED_TOKEN = "/" + VERSION_V2 + "/registration/mobile/login/userAuthorizedToken";
        public const string CREATE_ABHA_ID_BY_AADHAAR_DEMO = "/" + VERSION_V1 + "/hid/benefit/createHealthId/demo/auth";

        public const string PUBLIC_CERT = "/" + VERSION_V1 + "/phr/public/certificate";
        public const string MOBILE_EMAIL_INIT = "/" + VERSION_V1 + "/phr/login/mobileEmail/init";
        public const string MOBILE_EMAIL_PRE_VERIFICATION = "/" + VERSION_V1 + "/phr/login/mobileEmail/preVerification";
        public const string MOBILE_EMAIL_GET_USERTOKEN = "/" + VERSION_V1 + "/phr/login/mobileEmail/getUserToken";
        public const string LINK_PHR_ADDRESS = "/" + VERSION_V1 + "/phr/profile/link/hid";
        public const string AUTH_MODE_FOR_HEALTH_ID = "/" + VERSION_V1 + "/phr/registration/hid/search/auth-methods";
        public const string TRANSACTION_INIT = "/" + VERSION_V1 + "/phr/login/init/transaction";
        public const string ABHA_ADDRESS_PROFILE = "/" + VERSION_V1 + "/phr/profile";
        public const string CHECK_ABHA_ADDRESS = "/" + VERSION_V1 + "/phr/search/isExist";
        public const string X_TOKEN_TYPE = "Bearer";
        public const string T_TOKEN_TYPE = "Bearer";
        public const string AUTHORIZATION = "Authorization";
        public const string BAHMNI_AUTH = "bahmni";
        public const string GATEWAY_AUTH = "gateway";
        public const string TIMESTAMP_FORMAT = "yyyy-MM-ddTHH:mm:ss.fffZ";

    }
}
