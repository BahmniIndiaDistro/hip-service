using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Logger;

namespace In.ProjectEKA.HipService.OpenMrs
{
    public class OpenMrsClient : IOpenMrsClient
    {
        private readonly HttpClient httpClient;
        private readonly OpenMrsConfiguration configuration;
        public OpenMrsClient(HttpClient httpClient, OpenMrsConfiguration openMrsConfiguration)
        {
            this.httpClient = httpClient;
            configuration = openMrsConfiguration;

            SettingUpHeaderAuthorization();
        }

        public async Task<HttpResponseMessage> GetAsync(string openMrsUrl)
        {
            var responseMessage = await httpClient.GetAsync(Path.Join(configuration.Url, openMrsUrl));

            Log.Debug(
                    $"Getting the data from OpenMrs url {responseMessage.RequestMessage.RequestUri}");
            if (!responseMessage.IsSuccessStatusCode)
            {
                if (!responseMessage.StatusCode.Equals(HttpStatusCode.BadRequest))
                {
                    var error = await responseMessage.Content.ReadAsStringAsync();
                    Log.Error($"Failure in getting the data from OpenMrs url {responseMessage.RequestMessage.RequestUri} with status code {responseMessage.StatusCode}" +
                    $" {error}");
                    throw new OpenMrsConnectionException();
                }
                Log.Error($"Failure in getting the data from OpenMrs url {responseMessage.RequestMessage.RequestUri} with status code {responseMessage.StatusCode}");
            }

            return responseMessage;
        }
        
        public async Task<HttpResponseMessage> PostAsync(string openMrsUrl, string jsonContent)
        {
            var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            var responseMessage = await httpClient.PostAsync(Path.Join(configuration.Url, openMrsUrl), httpContent);

            Log.Debug(
                    $"Posting the data with OpenMrs url {responseMessage.RequestMessage.RequestUri}");
            if (!responseMessage.IsSuccessStatusCode)
            {
                var error = await responseMessage.Content.ReadAsStringAsync();
                Log.Error(
                    $"Failure in posting the data into OpenMrs url {responseMessage.RequestMessage.RequestUri} with status code {responseMessage.StatusCode}" +
                    $" {error}");
                throw new OpenMrsConnectionException();
            }

            return responseMessage;
        }

        private void SettingUpHeaderAuthorization()
        {
            var authToken = Encoding.ASCII.GetBytes($"{configuration.Username}:{configuration.Password}");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(authToken));
        }
    }
}