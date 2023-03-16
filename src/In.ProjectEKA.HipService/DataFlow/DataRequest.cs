using In.ProjectEKA.HipLibrary.Patient.Model;
namespace In.ProjectEKA.HipService.DataFlow
{
    using System.Collections.Generic;
    using Common.Model;
    using System;

    public class DataRequest
    {
        public DataRequest(IEnumerable<GrantedContext> careContexts,
            DateRange dateRange,
            string dataPushUrl,
            IEnumerable<HiType> hiType,
            string transactionId,
            KeyMaterial keyMaterial,
            string gatewayId,
            string consentId,
            string cmSuffix,
            string correlationId,
            Guid patientUuid
            )
        {
            CareContexts = careContexts;
            DateRange = dateRange;
            DataPushUrl = dataPushUrl;
            HiType = hiType;
            TransactionId = transactionId;
            KeyMaterial = keyMaterial;
            GatewayId = gatewayId;
            ConsentId = consentId;
            CmSuffix = cmSuffix;
            CorrelationId = correlationId;
            PatientUuid = patientUuid;
        }

        public IEnumerable<GrantedContext> CareContexts { get; }
        public DateRange DateRange { get; }
        public string DataPushUrl { get; }
        public IEnumerable<HiType> HiType { get; }
        public string TransactionId { get; }
        public KeyMaterial KeyMaterial { get; }
        public string GatewayId { get; }
        public string ConsentId { get; }
        public string CmSuffix { get; }
        public string CorrelationId { get; }
        public Guid PatientUuid { get; }
    }
}