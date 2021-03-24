using Microsoft.EntityFrameworkCore;

namespace In.ProjectEKA.HipService.UserAuth.Database
{
    public class AuthContext : DbContext
    {
        public AuthContext(DbContextOptions<AuthContext> options) : base(options)
        {
        }

        public DbSet<AuthConfirm> AuthConfirm { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AuthConfirm>(builder =>
            {
                builder.HasKey(p => p.TransactionId);
                builder.Property(p => p.HealthId);
                builder.Property(p => p.TransactionId);
                builder.Property(p => p.AccessToken);
            });
        }

    }
}