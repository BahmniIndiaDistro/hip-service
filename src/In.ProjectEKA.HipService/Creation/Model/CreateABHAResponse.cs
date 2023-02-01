using System;
using System.Collections.Generic;

namespace In.ProjectEKA.HipService.Creation.Model
{
    public class CreateABHAResponse
    {
        public CreateABHAResponse(string token, string refreshToken)
        {
            this.token = token;
            this.refreshToken = refreshToken;
        }
        public string token { get; }
        public string refreshToken { get; }
    }
}