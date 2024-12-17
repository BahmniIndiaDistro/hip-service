using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace In.ProjectEKA.HipService.Verification.Model
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum IdentifierType
    {
        ABHA_NUMBER,
        MOBILE_NUMBER,
        AADHAAR_NUMBER
    }
}