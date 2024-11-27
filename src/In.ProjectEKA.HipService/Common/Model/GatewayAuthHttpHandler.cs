using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Log = Serilog.Log;

namespace In.ProjectEKA.HipService.Common.Model;

public class GatewayAuthHttpHandler : HttpClientHandler
{
    public GatewayAuthHttpHandler(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    private IConfiguration Configuration;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        request.Headers.Add("X-CM-ID", Configuration.GetValue<string>("Gateway:cmSuffix"));
        request.Headers.Add("REQUEST-ID", Guid.NewGuid().ToString());
        request.Headers.Add("TIMESTAMP", DateTime.UtcNow.ToString(Constants.TIMESTAMP_FORMAT));
        HttpResponseMessage responseMessage = await base.SendAsync(request, cancellationToken);
        return responseMessage;
    }
}