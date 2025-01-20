using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth.Model;

namespace In.ProjectEKA.HipService.Link
{
    public interface ICareContextService
    {
        public Task<Tuple<GatewayAddContextsRequestRepresentation, ErrorRepresentation>> AddContextsResponse(
            AddContextsRequest addContextsRequest, string cmSuffix, Guid requestId);

        public Tuple<GatewayNotificationContextRepresentation, ErrorRepresentation> NotificationContextResponse(
            NotifyContextRequest notifyContextRequest);

        public Task CallNotifyContext(NewContextRequest newContextRequest,
            CareContextRepresentation context);

        public Task CallAddContext(NewContextRequest newContextRequest);
        public bool IsLinkedContext(List<string> careContexts, string context);
        Task SetAccessToken(string patientReferenceNumber);
    }
}