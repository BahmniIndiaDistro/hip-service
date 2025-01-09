namespace In.ProjectEKA.HipLibrary.Patient.Model
{
    public static class ErrorCode
    {
        public const string NoPatientFound = "ABDM-1010";
        public const string MultiplePatientsFound = "3403";
        public const string CareContextNotFound = "ABDM-1012";
        public const string OtpInValid = "ABDM-1035";
        public const string OtpExpired = "ABDM-1035";
        public const string OtpGenerationFailed = "3501";
        public const string NoLinkRequestFound = "3413";
        public const string ServerInternalError = "3500";
        public const string DiscoveryRequestNotFound = "3407";
        public const string ContextArtefactIdNotFound = "3416";
        public const string InvalidToken = "3401";
        public const string HealthInformationNotFound = "3502";
        public const string LinkExpired = "3408";
        public const string ExpiredKeyPair = "3410";
        public const string FailedToGetLinkedCareContexts = "3507";
        public const string DuplicateDiscoveryRequest = "3409";
        public const string DuplicateRequestId = "3429";
        public const string CareContextConfiguration = "3430";
        public const string OpenMrsConnection = "3431";
        public const string HeartBeat = "3432";
        public const string InvalidHealthId = "3433";
        public const string DuplicateAuthConfirmRequest = "3434";
        public const string GatewayTimedOut = "3435";
        public const string BadRequest = "3400";
        public const string ConsentNotGranted = "1428";
    }
}