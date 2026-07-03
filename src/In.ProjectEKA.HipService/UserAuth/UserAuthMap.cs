using System;
using System.Collections.Generic;
using System.Linq;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Common.Model;
using In.ProjectEKA.HipService.Link.Model;
using In.ProjectEKA.HipService.UserAuth.Model;
using Microsoft.AspNetCore.Http;

namespace In.ProjectEKA.HipService.UserAuth
{
    public static class UserAuthMap{
        public const string PhoneTimestampSeparator = "###";
        public static Dictionary<Guid, List<Mode>> RequestIdToAuthModes = new Dictionary<Guid, List<Mode>>();
        public static Dictionary<Guid, string> RequestIdToTransactionIdMap = new Dictionary<Guid, string>();
        public static Dictionary<Guid, string> RequestIdToAccessToken = new Dictionary<Guid, string>();
        public static Dictionary<string, string> HealthIdToTransactionId = new Dictionary<string, string>();
        public static Dictionary<Guid, AuthConfirmPatient> RequestIdToPatientDetails = new Dictionary<Guid, AuthConfirmPatient>();
        public static Dictionary<Guid, Error> RequestIdToErrorMessage = new Dictionary<Guid, Error>();
        public static Dictionary<string, string> HealthIdToAccessToken = new Dictionary<string, string>();
        public static Dictionary<string, string> RequestIdToHipId = new Dictionary<string, string>();
        public static Dictionary<string, string> HealthIdToLatestVisitUuid = new Dictionary<string, string>();
        public static Dictionary<string, List<string>> HealthIdToPhoneNumber = new Dictionary<string, List<string>>();
        public static Dictionary<Guid, AuthNotifyStatus> TransactionIdToAuthNotifyStatus = new Dictionary<Guid, AuthNotifyStatus>();
        public static Dictionary<Guid, AuthConfirmPatient> TransactionIdToPatientDetails = new Dictionary<Guid, AuthConfirmPatient>();
        public static Dictionary<string, int> ErrorCodeToStatusCode = new Dictionary<string, int>()
        {
            {ErrorCode.BadRequest, StatusCodes.Status400BadRequest},
            {ErrorCode.GatewayTimedOut, StatusCodes.Status504GatewayTimeout},
            {ErrorCode.ServerInternalError, StatusCodes.Status500InternalServerError},
            {ErrorCode.ConsentNotGranted, StatusCodes.Status504GatewayTimeout}
        };

        // public static string ResolveHipIdForHealthId(string healthId, BahmniConfiguration bahmniConfiguration)
        // {
        //     var hipId = bahmniConfiguration.GetDefaultHfrId();
        //     if (!string.IsNullOrEmpty(healthId)
        //         && HealthIdToLatestVisitUuid.TryGetValue(healthId, out var visitUuid))
        //     {
        //         var visitHipId = bahmniConfiguration.GetHfrIdByVisitUuid(visitUuid);
        //         if (!string.IsNullOrEmpty(visitHipId))
        //             hipId = visitHipId;
        //     }
        //     return hipId;
        // }

        public static void UpdateHealthIdToLatestVisitUuid(string healthId, string visitUuid)
        {
            if (string.IsNullOrEmpty(healthId) || string.IsNullOrEmpty(visitUuid))
                return;

            if (HealthIdToLatestVisitUuid.ContainsKey(healthId))
                HealthIdToLatestVisitUuid[healthId] = visitUuid;
            else
                HealthIdToLatestVisitUuid.Add(healthId, visitUuid);
        }

        public static void UpdateHealthIdToPhoneNumber(string phoneNumber, string healthId)
        {
            if (string.IsNullOrEmpty(phoneNumber) || string.IsNullOrEmpty(healthId))
                return;

            var normalizedPhone = NormalizePhoneNumber(phoneNumber);
            var compositeEntry = CreatePhoneEntry(normalizedPhone);

            if (!HealthIdToPhoneNumber.TryGetValue(healthId, out var phoneEntries))
            {
                phoneEntries = new List<string>();
            }
            phoneEntries.Add(compositeEntry);
            HealthIdToPhoneNumber[healthId] = phoneEntries;
        }

        public static string GetHealthIdByPhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return null;

            var normalizedPhone = NormalizePhoneNumber(phoneNumber);

            return HealthIdToPhoneNumber
                .SelectMany(kvp => kvp.Value.Select(entry => new { HealthId = kvp.Key, Entry = entry }))
                .Where(x => ExtractPhoneNumber(x.Entry) == normalizedPhone)
                .OrderByDescending(x => ExtractTimestamp(x.Entry))
                .Select(x => x.HealthId)
                .FirstOrDefault();
        }

        public static string GetLatestPhoneNumber(string healthId)
        {
            if (string.IsNullOrEmpty(healthId)
                || !HealthIdToPhoneNumber.TryGetValue(healthId, out var phoneEntries)
                || phoneEntries.Count == 0)
                return null;

            return phoneEntries
                .OrderByDescending(ExtractTimestamp)
                .Select(ExtractPhoneNumber)
                .FirstOrDefault();
        }

        public static string CreatePhoneEntry(string normalizedPhone)
        {
            return $"{normalizedPhone}{PhoneTimestampSeparator}{DateTime.UtcNow:O}";
        }

        public static string ExtractPhoneNumber(string compositeEntry)
        {
            if (string.IsNullOrEmpty(compositeEntry))
                return compositeEntry;

            var separatorIndex = compositeEntry.LastIndexOf(PhoneTimestampSeparator, StringComparison.Ordinal);
            return separatorIndex < 0 ? compositeEntry : compositeEntry.Substring(0, separatorIndex);
        }

        public static DateTime ExtractTimestamp(string compositeEntry)
        {
            if (string.IsNullOrEmpty(compositeEntry))
                return DateTime.MinValue;

            var separatorIndex = compositeEntry.LastIndexOf(PhoneTimestampSeparator, StringComparison.Ordinal);
            if (separatorIndex < 0 || separatorIndex + PhoneTimestampSeparator.Length > compositeEntry.Length)
                return DateTime.MinValue;

            return DateTime.Parse(
                compositeEntry.Substring(separatorIndex + PhoneTimestampSeparator.Length),
                null,
                System.Globalization.DateTimeStyles.RoundtripKind);
        }

        public static string NormalizePhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return phoneNumber;

            phoneNumber = phoneNumber.Trim();
            if (phoneNumber.StartsWith("+91"))
                phoneNumber = phoneNumber.Substring(3);
            else if (phoneNumber.StartsWith("91"))
                phoneNumber = phoneNumber.Substring(2);
            return phoneNumber;
        }
    }
}
