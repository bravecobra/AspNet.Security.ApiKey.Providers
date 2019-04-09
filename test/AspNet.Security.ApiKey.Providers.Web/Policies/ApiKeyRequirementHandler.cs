using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AspNet.Security.ApiKey.Providers.Web.Policies
{
    /// <summary>
    /// 
    /// </summary>
    public class ApiKeyRequirementHandler : AuthorizationHandler<ApiKeyRequirement>
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="requirement"></param>
        /// <returns></returns>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyRequirement requirement)
        {
            if (context.Resource is AuthorizationFilterContext authorizationFilterContext)
            {
                if (!context.User.HasClaim(c => c.Type == "ApiKey"))
                {
                    return Task.CompletedTask;
                }

                var principalApiKey = context.User.FindFirst(c => c.Type == "ApiKey").Value;
                if (principalApiKey == requirement.ApiKey)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }
}
