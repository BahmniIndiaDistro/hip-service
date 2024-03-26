using System.Reflection;
using In.ProjectEKA.HipLibrary.Patient.Model;
using In.ProjectEKA.HipService.Logger;

namespace In.ProjectEKA.HipService.DataFlow
{
    using System.Threading.Tasks;
    using HipLibrary.Patient;

    public class DataFlowMessageHandler
    {
        private readonly ICollectHipService collectHipService;
        private readonly DataEntryFactory dataEntryFactory;
        private readonly DataFlowClient dataFlowClient;

        public DataFlowMessageHandler(
            ICollectHipService collectHipService,
            DataFlowClient dataFlowClient,
            DataEntryFactory dataEntryFactory)
        {
            this.collectHipService = collectHipService;
            this.dataFlowClient = dataFlowClient;
            this.dataEntryFactory = dataEntryFactory;
        }

        public async Task HandleDataFlowMessage(TraceableDataRequest dataRequest)
        {
            var sentKeyMaterial = dataRequest.KeyMaterial;
            var data = await collectHipService.CollectData(dataRequest).ConfigureAwait(false);
            var encryptedEntries = data.FlatMap(entries =>
                dataEntryFactory.Process(entries, sentKeyMaterial, dataRequest.TransactionId));
            encryptedEntries.MatchSome(async entries =>
                await dataFlowClient.SendDataToHiu(dataRequest,
                    entries.Entries,
                    entries.KeyMaterial).ConfigureAwait(false));
        }
    }
}