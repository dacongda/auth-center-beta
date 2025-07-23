using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Diagnostics;

namespace AuthCenter.Handler
{
    public class GlobalExceptionHandler : IExceptionHandler
    {
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            var resp = JSONResult.ResponseError(exception.Message);

            httpContext.Response.ContentType = "application/json";

            await httpContext.Response.WriteAsJsonAsync(resp, cancellationToken);

            return true;
        }
    }
}
