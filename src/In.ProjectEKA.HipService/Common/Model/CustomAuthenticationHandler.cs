using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.OpenMrs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;

namespace In.ProjectEKA.HipService.Common.Model
{
    public class CustomAuthenticationHandler : AuthenticationHandler<CustomAuthenticationOptions>
    {
        
        private readonly OpenMrsConfiguration _configuration;
        public CustomAuthenticationHandler(IOptionsMonitor<CustomAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, OpenMrsConfiguration configuration)
            : base(options, logger, encoder, clock)
        {
            _configuration = configuration;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            
            if (Request.Cookies.ContainsKey(Constants.REPORTING_SESSION))
            {
                string sessionId = Request.Cookies[Constants.REPORTING_SESSION];
                var httpClient = new HttpClient();
                
                var request = new HttpRequestMessage(HttpMethod.Get, _configuration.Url + Constants.WHO_AM_I);
                request.Headers.Add("Cookie", Constants.OPENMRS_SESSION_ID_COOKIE_NAME + "=" + sessionId);

                var response = await httpClient.SendAsync(request).ConfigureAwait(false);
                
                if (response.StatusCode == HttpStatusCode.Redirect)
                {
                    // Handle the redirect by making a new request with the updated URL
                    var redirectUrl = response.Headers.Location.ToString();
                    request = new HttpRequestMessage(HttpMethod.Get, redirectUrl);
                    response = await httpClient.SendAsync(request).ConfigureAwait(false);
                }
                
                if (!response.IsSuccessStatusCode)
                {
                    return AuthenticateResult.Fail("Failed to authenticate. Please check your credentials.");
                }
                Request.HttpContext.Items[Constants.SESSION_ID] = sessionId;
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "username"),
                    // Add any additional claims as needed
                };

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            
            return AuthenticateResult.Fail("Failed to authenticate. Please check your credentials.");
        }

    }


}