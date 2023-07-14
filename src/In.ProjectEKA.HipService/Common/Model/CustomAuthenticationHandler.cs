using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using In.ProjectEKA.HipService.OpenMrs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace In.ProjectEKA.HipService.Common.Model
{
    using static Constants;
    public class CustomAuthenticationHandler : AuthenticationHandler<CustomAuthenticationOptions>
    {
        
        private readonly OpenMrsConfiguration _configuration;
        private readonly JwtConfiguration _jwtConfiguration;
        private string unauthorizedError = "Failed to authenticate. Please check your credentials.";
        public CustomAuthenticationHandler(IOptionsMonitor<CustomAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, OpenMrsConfiguration configuration, JwtConfiguration jwtConfiguration)
            : base(options, logger, encoder, clock)
        {
            _configuration = configuration;
            _jwtConfiguration = jwtConfiguration;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            
            if (Request.Cookies.ContainsKey(REPORTING_SESSION))
            {
                return await PerformCookieAuth();
            }

            if (Request.Headers.ContainsKey(AUTHORIZATION))
            {
                return await PerformTokenAuth();
            }
            return AuthenticateResult.Fail(unauthorizedError);

        }

        private async Task<AuthenticateResult> PerformTokenAuth()
        {
            string authorizationHeader = Request.Headers[AUTHORIZATION];
            if (authorizationHeader.StartsWith(X_TOKEN_TYPE, StringComparison.OrdinalIgnoreCase))
            {
                string token = authorizationHeader.Substring($"{X_TOKEN_TYPE} ".Length).Trim();

                var key = await GetPublicKeysFromKeycloakAsync(new JwtSecurityToken(token).Header.Kid);

                ISecurityTokenValidator tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateLifetime = true,
                    ValidAudience = _jwtConfiguration.Audience,
                    ValidIssuer = _jwtConfiguration.Authority,
                    IssuerSigningKey = key
                };

                try
                {
                    var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                    var identity = principal.Identity as ClaimsIdentity;
                    var claims = identity.Claims.ToList();

                    string sid = claims.FirstOrDefault(c => c.Type == "sid")?.Value;

                    Request.HttpContext.Items[SESSION_ID] = sid;

                    var ticket = new AuthenticationTicket(principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }
                catch (Exception)
                {
                    return AuthenticateResult.Fail(unauthorizedError);
                }
            }
            return AuthenticateResult.Fail(unauthorizedError);
        }

        private async Task<AuthenticateResult> PerformCookieAuth()
        {
            string sessionId = Request.Cookies[REPORTING_SESSION];
            var httpClient = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Get, _configuration.Url + WHO_AM_I);
            request.Headers.Add("Cookie", OPENMRS_SESSION_ID_COOKIE_NAME + "=" + sessionId);

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
                return AuthenticateResult.Fail(unauthorizedError);
            }

            Request.HttpContext.Items[SESSION_ID] = sessionId;
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "username"),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private static byte[] Base64UrlDecode(string base64Url)
        {
            string base64 = base64Url.Replace('_', '/').Replace('-', '+');
            
            while (base64.Length % 4 != 0)
            {
                base64 += '=';
            }

            return Convert.FromBase64String(base64);
        }
        
        private async Task<SecurityKey> GetPublicKeysFromKeycloakAsync(string kid)
        {

            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(_jwtConfiguration.Cert);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            
            var json = await response.Content.ReadAsStringAsync();
            var jwks = new JsonWebKeySet(json);

            foreach (var key in jwks.Keys)
            {
                if (key.Kid.Equals(kid))
                {
                    var certificateBytes = Base64UrlDecode(key.X5c[0]);
                    var certificate = new X509Certificate2(certificateBytes);

                    var securityKey = new X509SecurityKey(certificate);
                    return securityKey;
                }

            }
            return null;
        }

    }
}


