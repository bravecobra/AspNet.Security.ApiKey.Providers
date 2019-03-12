﻿using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.ApiKey.Providers.Events
{
    public class ApiKeyValidatedContext : ResultContext<ApiKeyOptions>
    {
        public ApiKeyValidatedContext(HttpContext context, AuthenticationScheme scheme, ApiKeyOptions options)
            : base(context, scheme, options)
        {
            Principal = new ClaimsPrincipal();
        }

        public string ApiKey { get; internal set; }
    }
}
