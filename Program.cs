using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.HostServices;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using StackExchange.Redis;
using System.Diagnostics;
using System.Linq;
using System.Threading.RateLimiting;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AuthCenterDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("UserContext") ?? throw new InvalidOperationException("Connection string 'UserContext' not found."))
    .UseSnakeCaseNamingConvention());

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("RedisContext");
    options.InstanceName = "AuthCenter";
});

// Add services to the container.
builder.Services.AddAuthentication(config =>
 {
     config.DefaultAuthenticateScheme = UserRoleAuthorizationHandler.UserRoleSchemeName;
     config.DefaultChallengeScheme = UserRoleAuthorizationHandler.UserRoleSchemeName;
     config.AddScheme<UserRoleAuthorizationHandler>(UserRoleAuthorizationHandler.UserRoleSchemeName, UserRoleAuthorizationHandler.UserRoleSchemeName);
     config.AddScheme<BasicAuthorizationHandler>(BasicAuthorizationHandler.BasicSchemeName, BasicAuthorizationHandler.BasicSchemeName);
     config.AddScheme<BearerAuthorizationHandler>(BearerAuthorizationHandler.BearerSchemeName, BearerAuthorizationHandler.BearerSchemeName);
 });
//builder.Services.AddAuthentication();
builder.Services.AddControllers().ConfigureApiBehaviorOptions(options =>
{
    options.InvalidModelStateResponseFactory = context =>
    {
        var error = new ValidationProblemDetails(context.ModelState);

        return new JsonResult(JSONResult.ResponseError(error.Title?.ToString() ?? ""));
    };
}).AddXmlDataContractSerializerFormatters().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
});

var sessionName = $"{builder.Configuration.GetSection("ServerStrings")["ServerName"]?.Replace(" ", "")}.Session";

builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.Name = sessionName;
    options.IdleTimeout = TimeSpan.FromMinutes(120);
    options.Cookie.MaxAge = TimeSpan.FromMinutes(120);
    options.Cookie.IsEssential = true;
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => options.CustomSchemaIds(x => x.FullName));
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddSingleton(ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("RedisContext") ?? "").GetDatabase(0));

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("login", httpContext =>
    {
        var sessionId = httpContext.Session.Id;

        if (sessionId != null)
        {
            return RateLimitPartition.GetFixedWindowLimiter(sessionId,
            partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1)
            });
        }

        return RateLimitPartition.GetNoLimiter("");
    });

    options.AddPolicy("userVerify", httpContext =>
    {
        var userId = httpContext.User.Identity?.Name;

        if (userId != null)
        {
            return RateLimitPartition.GetFixedWindowLimiter(userId,
            partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5)
            });
        }

        return RateLimitPartition.GetNoLimiter("");
    });
});

builder.Services.AddHostedService<CleanExpiredTokenService>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthCenterDbContext>();
    db.Database.Migrate();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

var currentDir = Directory.GetCurrentDirectory();
var baseDir = Path.Combine(currentDir, builder.Configuration["baseDir"] ?? "./upload");

app.UseForwardedHeaders();

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(baseDir),
    RequestPath = "/api/static"
});
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseSession();

app.Use(async (context, next) =>
{
    // Session Id will always change until first value is set
    if (!context.Request.Cookies.TryGetValue(sessionName, out _))
    {
        context.Session.SetString("-", "");
    }
    var logger = context.RequestServices.GetService<ILoggerFactory>()?
        .CreateLogger("PerformanceLog");

    var profiler = new Stopwatch();
    profiler.Start();
    await next();
    profiler.Stop();

    logger?.LogInformation("TraceId:{TraceId}, RequestMethod:{RequestMethod}, RequestPath:{RequestPath}, ElapsedMilliseconds:{ElapsedMilliseconds}, Response StatusCode: {StatusCode}",
                            context.TraceIdentifier, context.Request.Method, context.Request.Path, profiler.ElapsedMilliseconds, context.Response.StatusCode);
});

app.UseRateLimiter();

app.MapControllers();
app.UseExceptionHandler(o => { });

app.Run();
