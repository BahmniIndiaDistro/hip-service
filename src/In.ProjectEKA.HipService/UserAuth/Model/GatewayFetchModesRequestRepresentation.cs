using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.UserAuth.Model
{
    public class GatewayFetchModesRequestRepresentation
    {
        public Guid requestId { get; }

        public string timestamp { get; }

        public FetchQuery query { get; }


        public GatewayFetchModesRequestRepresentation(Guid requestId, string timestamp, FetchQuery query)
        {
            this.requestId = requestId;
            this.timestamp = timestamp;
            this.query = query;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}