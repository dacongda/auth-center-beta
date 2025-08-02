using AuthCenter.Models;
using AuthCenter.Utils;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.EntityFrameworkCore.Query;
using NuGet.Protocol;
using System.Linq.Expressions;

namespace AuthCenter.Data
{
    public static class DbFuncExtension
    {
        public static Expression<Func<SetPropertyCalls<TEntity>, SetPropertyCalls<TEntity>>> Append<TEntity>(
    this Expression<Func<SetPropertyCalls<TEntity>, SetPropertyCalls<TEntity>>> left,
    Expression<Func<SetPropertyCalls<TEntity>, SetPropertyCalls<TEntity>>> right)
        {
            var replace = new ReplacingExpressionVisitor(right.Parameters, [left.Body]);
            var combined = replace.Visit(right.Body);
            return Expression.Lambda<Func<SetPropertyCalls<TEntity>, SetPropertyCalls<TEntity>>>(combined, left.Parameters);
        }
    }

    public class AuthCenterDbContext : DbContext
    {
        public AuthCenterDbContext(DbContextOptions<AuthCenterDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> User { get; set; } = default!;
        public DbSet<Application> Application { get; set; } = default!;
        public DbSet<Cert> Cert { get; set; } = default!;
        public DbSet<Group> Group { get; set; } = default!;
        public DbSet<Provider> Provider { get; set; } = default!;
        public DbSet<WebAuthnCredential> WebAuthnCredential { get; set; } = default!;


        public override int SaveChanges()
        {
            var entityEntries = ChangeTracker.Entries().ToList();
            foreach (var entry in entityEntries)
            {
                if (entry.State == EntityState.Added && !entry.Metadata.IsOwned())
                    Entry(entry.Entity).Property(nameof(BaseModel.CreatedAt)).CurrentValue = DateTime.UtcNow;

                if (entry.State == EntityState.Modified && !entry.Metadata.IsOwned())
                    Entry(entry.Entity).Property(nameof(BaseModel.UpdatedAt)).CurrentValue = DateTime.UtcNow;
            }
            return base.SaveChanges();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // 群组用户一对多关系
            modelBuilder.Entity<Group>()
                .HasMany<User>()
                .WithOne(e => e.Group)
                .HasForeignKey(e => e.GroupId)
                .IsRequired(false);

            // 群组默认应用一对一
            modelBuilder.Entity<Group>()
                .HasOne(e => e.DefaultApplication)
                .WithOne()
                .HasForeignKey<Group>(g => g.DefaultApplicationId)
                //.HasConstraintName("fk_default_application")
                .IsRequired(false);

            // 应用群组一对多
            modelBuilder.Entity<Application>()
                .HasOne(a => a.Group)
                .WithMany()
                .HasForeignKey(a => a.GroupId)
                //.HasConstraintName("fk_parent_group")
                .IsRequired(false);

            // 应用证书多对一关系
            modelBuilder.Entity<Cert>()
                .HasMany<Application>()
                .WithOne(e => e.Cert)
                .HasForeignKey(e => e.CertId)
                .IsRequired(false);

            modelBuilder.Entity<Application>()
                .OwnsMany(e => e.ProviderItems, builder =>
                {
                    builder.ToJson();
                    builder.WithOwner().HasForeignKey(f => f.Id);
                });

            base.OnModelCreating(modelBuilder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);

            optionsBuilder.ConfigureWarnings(warnings =>
                warnings.Ignore(RelationalEventId.PendingModelChangesWarning)).UseSeeding((context, _) =>
                {
                    var defaultCert = context.Set<Cert>().FirstOrDefault(a => a.Id == 1);
                    if (defaultCert == null)
                    {
                        var newCert = CertUtil.CreateNewCert("default", "RSA", 256, 2048, "jwk", $"CN=Auth Center", null);
                        newCert.Id = 1;
                        context.Set<Cert>().Add(newCert);
                        context.SaveChanges();
                    }

                    var defaultGroup = context.Set<Group>().FirstOrDefault(g => g.Name == "built-in");
                    if (defaultGroup == null)
                    {
                        context.Set<Group>().Add(new Group
                        {
                            Id = 1,
                            Name = "built-in",
                            DisplayName = "Built in group",
                            DefaultRoles = ["admin"],
                            ParentChain = "built-in"
                        });
                    }

                    var defaultApp = context.Set<Application>().FirstOrDefault(a => a.Name == "default");
                    if (defaultApp == null)
                    {
                        context.Set<Application>().Add(new Application
                        {
                            Id = 1,
                            Name = "default",
                            ClientId = Guid.NewGuid().ToString("N"),
                            ClientSecret = Guid.NewGuid().ToString("N"),
                            CertId = 1,
                            GroupId = 1,
                            Scopes = ["email", "phone"]
                        });

                        defaultGroup = context.Set<Group>().FirstOrDefault(g => g.Name == "built-in");
                        defaultGroup.DefaultApplicationId = 1;
                        context.Set<Group>().Update(defaultGroup);
                    }

                    var defaultProvider = context.Set<Provider>().FirstOrDefault(a => a.Name == "captcha_default");
                    if (defaultProvider == null)
                    {
                        context.Set<Provider>().Add(new Provider
                        {
                            Id = 1,
                            Name = "captcha_default",
                            Type = "Captcha",
                            SubType = "Default"
                        });
                    }

                    var defaultUser = context.Set<User>().FirstOrDefault(u => u.Id == 1);
                    if (defaultUser == null)
                    {
                        context.Set<User>().Add(new User()
                        {
                            Id = 1,
                            Number = "admin",
                            Name = "admin",
                            Password = BCrypt.Net.BCrypt.HashPassword("rootroot"),
                            Roles = ["admin"],
                            GroupId = 1,
                            IsAdmin = true
                        });
                    }

                    context.SaveChanges();
                });
        }
    }
}
