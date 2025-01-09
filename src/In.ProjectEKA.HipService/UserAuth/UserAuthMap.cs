using System;
using System.Collections.Generic;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.AspNetCore.Http;

namespace In.ProjectEKA.HipService.UserAuth
{
    public static class UserAuthMap{
        public static Dictionary<Guid, List<Mode>> RequestIdToAuthModes = new Dictionary<Guid, List<Mode>>();
        public static Dictionary<Guid, string> RequestIdToTransactionIdMap = new Dictionary<Guid, string>();
        public static Dictionary<Guid, string> RequestIdToAccessToken = new Dictionary<Guid, string>();
        public static Dictionary<string, string> HealthIdToTransactionId = new Dictionary<string, string>();
        public static Dictionary<Guid, AuthConfirmPatient> RequestIdToPatientDetails = new Dictionary<Guid, AuthConfirmPatient>();
        public static Dictionary<Guid, Error> RequestIdToErrorMessage = new Dictionary<Guid, Error>();
        public static Dictionary<string, string> HealthIdToAccessToken = new Dictionary<string, string>();
        public static Dictionary<Guid, AuthNotifyStatus> TransactionIdToAuthNotifyStatus = new Dictionary<Guid, AuthNotifyStatus>();
        public static Dictionary<Guid, AuthConfirmPatient> TransactionIdToPatientDetails = new Dictionary<Guid, AuthConfirmPatient>();
        public static Dictionary<string, int> ErrorCodeToStatusCode = new Dictionary<string, int>()
        {
            {ErrorCode.BadRequest, StatusCodes.Status400BadRequest},
            {ErrorCode.GatewayTimedOut, StatusCodes.Status504GatewayTimeout},
            {ErrorCode.ServerInternalError, StatusCodes.Status500InternalServerError},
            {ErrorCode.ConsentNotGranted, StatusCodes.Status504GatewayTimeout}
        };
    }
}