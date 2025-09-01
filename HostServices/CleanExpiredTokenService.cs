using AuthCenter.Data;
using Microsoft.EntityFrameworkCore;
using System.Threading;

namespace AuthCenter.HostServices
{
    public class CleanExpiredTokenService(IServiceScopeFactory scopeFactory, ILogger<CleanExpiredTokenService> logger) : IHostedService, IDisposable
    {
        private readonly ILogger<CleanExpiredTokenService> _logger = logger;
        private Timer? _timer = null;

        public async Task StartAsync(CancellationToken stoppingToken)
        {
            
            //context.Database.EnsureCreated(stoppingToken);

            _logger.LogInformation("Clean expired session service is running.");
            _timer = new Timer(CleanExpiredToken, null, TimeSpan.Zero, TimeSpan.FromHours(2));
        }

        private async void CleanExpiredToken(object? state)
        {
            using var scope = scopeFactory.CreateScope();
            using var context = scope.ServiceProvider.GetRequiredService<AuthCenterDbContext>();
            _logger.LogInformation("cleaning expired session token");
            var count = await context!.UserSessions.Where(us => us.ExpiredAt < DateTimeOffset.UtcNow).ExecuteDeleteAsync();
            _logger.LogInformation("{count} Session has been cleaned", count);
        }

        public Task StopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Clean expired session service is stopping.");

            _timer?.Change(Timeout.Infinite, 0);

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }
    }
}
