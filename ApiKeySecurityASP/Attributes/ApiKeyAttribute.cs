using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace ApiKeySecurityASP.Attributes
{
    [AttributeUsage(validOn: AttributeTargets.Class)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var appSettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apiKeyName = appSettings.GetValue<string>("ApiKeyName"); //Get value Appsettings.json file
            var apiKeyValue= appSettings.GetValue<string>("ApiKeyValue");

            if (!context.HttpContext.Request.Headers.TryGetValue(apiKeyName, out var extractedApiKey)) {
                context.Result = new ContentResult()
                {
                    StatusCode=401,
                    Content= "ApiKeyName was not provided or was invalid"
                };
                return;
            }

            if(!apiKeyValue.Equals(extractedApiKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "Unauthorized Client"
                };
                return;
            }
            await next();
        }
    }
}
