using AuthCenter.Data;
using AuthCenter.Handler;
using AuthCenter.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using StackExchange.Redis;
using System.Configuration;
using System.Diagnostics;
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
}).AddXmlDataContractSerializerFormatters().AddJsonOptions(options=>
{
    options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
});


// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => options.CustomSchemaIds(x => x.FullName));
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddSingleton(ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("RedisContext") ?? "").GetDatabase(0));

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

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

app.Use(async (context, next) =>
{
    var profiler = new Stopwatch();
    profiler.Start();
    await next();
    profiler.Stop();

    var logger = context.RequestServices.GetService<ILoggerFactory>()?
        .CreateLogger("PerformanceLog");
    logger?.LogInformation("TraceId:{TraceId}, RequestMethod:{RequestMethod}, RequestPath:{RequestPath}, ElapsedMilliseconds:{ElapsedMilliseconds}, Response StatusCode: {StatusCode}",
                            context.TraceIdentifier, context.Request.Method, context.Request.Path, profiler.ElapsedMilliseconds, context.Response.StatusCode);
});

var currentDir = Directory.GetCurrentDirectory();
var baseDir = Path.Combine(currentDir, builder.Configuration.GetConnectionString("baseDir") ?? "./upload");

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(baseDir),
    RequestPath = "/api/static"
});

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.UseExceptionHandler(o => { });

app.Run();
