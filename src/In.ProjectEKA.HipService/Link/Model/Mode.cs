using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace In.ProjectEKA.HipService.Link.Model
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum Mode
    {
        MOBILE_OTP,
        AADHAAR_OTP,
        PASSWORD,
        DEMOGRAPHICS,
        DIRECT
    }
}