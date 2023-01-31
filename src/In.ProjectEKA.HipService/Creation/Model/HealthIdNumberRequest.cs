using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class HealthIdNumberRequest
    {
        public string healhtIdNumber;

        public string authMethod;

        public HealthIdNumberRequest(string authMethod, string healhtIdNumber)
        {
            this.authMethod = authMethod;
            this.healhtIdNumber = healhtIdNumber;
        }
        
        [JsonConstructor]
        public HealthIdNumberRequest(string healthIdNumber)
        {
            this.healhtIdNumber = healthIdNumber;
        }
    }
}