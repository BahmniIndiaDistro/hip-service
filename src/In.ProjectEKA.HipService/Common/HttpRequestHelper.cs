namespace In.ProjectEKA.HipService.Common
{
    using System;
    using System.Net.Http;
    using System.Net.Mime;
    using System.Text;
    using Microsoft.Net.Http.Headers;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;
    using static Constants;

    public static class HttpRequestHelper
    {
        public static HttpRequestMessage CreateHttpRequest<T>(
            HttpMethod method,
            string url,
            T content,
            string token,
            string cmSuffix,
            string correlationId,
            string xtoken = null,
            string tToken = null,
            string transactionId = null)
        {
            HttpRequestMessage httpRequestMessage = new HttpRequestMessage(method, new Uri($"{url}"));
            ;
            if (content != null)
            {
                var json = JsonConvert.SerializeObject(content, new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore,
                    ContractResolver = new DefaultContractResolver
                    {
                        NamingStrategy = new CamelCaseNamingStrategy()
                    }
                });
                httpRequestMessage.Content = new StringContent(json, Encoding.UTF8, MediaTypeNames.Application.Json);
            }

            if (token != null) // our token to authenticate with ABDM gateway
                httpRequestMessage.Headers.Add(HeaderNames.Authorization, token);
            if (xtoken != null) //patient token
                httpRequestMessage.Headers.Add("X-Token", xtoken);
            if (tToken != null)
                httpRequestMessage.Headers.Add("T-token", tToken);
            if (cmSuffix != null)// Consent Manager ID
                httpRequestMessage.Headers.Add("X-CM-ID", cmSuffix);
            if (correlationId != null) // Track request end to end
                httpRequestMessage.Headers.Add(CORRELATION_ID, correlationId);
            if (transactionId != null) // To follow the sequence of our request
                httpRequestMessage.Headers.Add("Transaction_Id", transactionId);
            httpRequestMessage.Headers.Add("REQUEST-ID", Guid.NewGuid().ToString());
            httpRequestMessage.Headers.Add("TIMESTAMP", DateTime.Now.ToString(TIMESTAMP_FORMAT));
            return httpRequestMessage;
        }

        public static HttpRequestMessage CreateHttpRequest<T>(HttpMethod method, string url, T content,
            String correlationId)
        {
            // ReSharper disable once IntroduceOptionalParameters.Global
            return CreateHttpRequest(method, url, content, null, null, correlationId);
        }
    }
}