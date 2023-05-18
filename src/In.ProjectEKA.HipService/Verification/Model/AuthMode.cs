using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace In.ProjectEKA.HipService.Verification.Model
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum AuthMode
    {
        MOBILE_OTP,
        AADHAAR_OTP
    }
}