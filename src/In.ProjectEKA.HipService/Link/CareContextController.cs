using System;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.Common;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.Logger;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace In.ProjectEKA.HipService.Link
{
    using static Constants;

    [ApiController]
    public class CareContextController : Controller
    {
        private readonly ICareContextService careContextService;
        private readonly ILinkPatientRepository linkPatientRepository;
        public CareContextController(
            ICareContextService careContextService,
            ILinkPatientRepository linkPatientRepository
        )
        {
            this.careContextService = careContextService;
            this.linkPatientRepository = linkPatientRepository;
            
        }
        
        [Authorize]
        [HttpPost(PATH_ON_NOTIFY_CONTEXTS)]
        public AcceptedResult HipLinkOnNotifyContexts(HipLinkOnNotifyConfirmation confirmation)
        {
            Log.Information("Link on-notify context received.");
            if (confirmation.Error != null)
                Log.Information($" Error Code:{confirmation.Error.Code}," +
                                $" Error Message:{confirmation.Error.Message}");
            else if (confirmation.Acknowledgement != null)
                Log.Information($" Acknowledgment Status:{confirmation.Acknowledgement.Status}");
            Log.Information($" Resp RequestId:{confirmation.Response.RequestId}");
            return Accepted();
        }

        [Route(PATH_NEW_CARECONTEXT)]
        public async Task<ActionResult> PassContext([FromBody] NewContextRequest newContextRequest)
        {
            var (careContexts, exception) =
                await linkPatientRepository.GetLinkedCareContextsOfPatient(newContextRequest.PatientReferenceNumber);
            foreach (var context in newContextRequest.CareContexts)
            {
                if (careContexts != null && careContextService.IsLinkedContext(careContexts, context.ReferenceNumber))
                {
                    await careContextService.CallNotifyContext(newContextRequest, context);
                }
                else
                {
                    await careContextService.CallAddContext(newContextRequest);
                }
            }
            return StatusCode(StatusCodes.Status200OK);
        }
    }
}