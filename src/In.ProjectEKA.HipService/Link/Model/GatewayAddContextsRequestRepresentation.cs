using System;
using Newtonsoft.Json;

namespace In.ProjectEKA.HipService.Link.Model
{
    public class GatewayAddContextsRequestRepresentation
    {
        public Guid RequestId { get; }
        public string Timestamp { get; }
        public AddCareContextsLink Link { get; }

        public GatewayAddContextsRequestRepresentation(Guid requestId, string timestamp, AddCareContextsLink link)
        {
            RequestId = requestId;
            Timestamp = timestamp;
            Link = link;
        }

        public string dump(Object o)
        {
            return JsonConvert.SerializeObject(o);
        }
    }
}