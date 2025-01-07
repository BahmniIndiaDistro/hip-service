using System.Text.Json;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient;
using In.ProjectEKA.HipService.Logger;

namespace In.ProjectEKA.HipService.OpenMrs
{
    public class OpenMrsPhoneNumberRepository : IPhoneNumberRepository
    {
        private readonly IOpenMrsClient openMrsClient;
        private readonly OpenMrsConfiguration openMrsConfiguration;
        public OpenMrsPhoneNumberRepository(IOpenMrsClient openMrsClient, OpenMrsConfiguration openMrsConfiguration)
        {
            this.openMrsClient = openMrsClient;
            this.openMrsConfiguration = openMrsConfiguration;
        }

        public async Task<string> GetPhoneNumber(string patientReferenceNumber)
        {
            var openmrsRestPatientPath = $"{DiscoveryPathConstants.OnRestPatientPath}/{patientReferenceNumber}?v=full";

            var response = await openMrsClient.GetAsync(openmrsRestPatientPath);
            var content = await response.Content.ReadAsStringAsync();

            var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;

            var person = root.GetProperty("person");
            var attributes = person.GetProperty("attributes");
            for (int i = 0; i < attributes.GetArrayLength(); i++)
            {
                var attributeTypeDisplay = attributes[i].GetProperty("attributeType").GetProperty("display").ToString();
                if (attributeTypeDisplay == openMrsConfiguration.PhoneNumber) {
                    return attributes[i].GetProperty("value").ToString();
                }
            }

            return null;
        }
    }
}