namespace In.ProjectEKA.HipService.DataFlow
{
    public static class MessagingQueueConstants
    {
        public static readonly string DataRequestExchangeName = "hiservice.exchange.dataflowrequest";
        public static readonly string DataRequestRoutingKey = "*.queue.durable.dataflowrequest6.#";
        public static readonly string DataRequestExchangeType = "topic";
    }
}