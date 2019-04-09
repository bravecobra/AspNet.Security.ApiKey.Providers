using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace AspNet.Security.ApiKey.Providers.Web.Policies
{

    // https://blog.dangl.me/archive/securing-aspnet-core-controllers-with-a-policy-and-api-keys/

    /// <summary>
    /// The APIKey requirement
    /// </summary>
    public class ApiKeyRequirement : IAuthorizationRequirement
    {
        /// <summary>The ApiKey to check</summary>
        public string ApiKey { get; set;}

        /// <summary>
        /// Construct an API key requirement
        /// </summary>
        /// <param name="apiKey"></param>
        public ApiKeyRequirement(string apiKey)
        {
            ApiKey = apiKey;
        }
    }
}
