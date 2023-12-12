using CourseWork.Models;
using Microsoft.EntityFrameworkCore;


namespace CourseWork.Infrastructure
{
    public class SeedData
    {
        public static void SeedDatabase(DataContext context)
        {
            context.Database.Migrate();

            if (!context.Products.Any())
            {
                Category tractors = new Category { Name = "Tractors", Slug = "tractors" };
                Category seeds = new Category { Name = "Seeds", Slug = "seeds" };

                context.Products.AddRange(
                        new Product
                        {
                            Name = "Compact Tractor",
                            Slug = "compact-tractor",
                            Description = "Good Compact Tractor",
                            Price = 1.50M,
                            Category = tractors,
                            Image = "compact-tractor.jpg"
                        },
                        new Product
                        {
                            Name = "Mid-Range Tractor",
                            Slug = "mid-range-tractor",
                            Description = "Super Mid-Range Tractor",
                            Price = 3M,
                            Category = tractors,
                            Image = "mid-range-tractor.jpg"
                        },
                        new Product
                        {
                            Name = "Utility Tractor",
                            Slug = "utility-tractor",
                            Description = "Best Utility Tractor",
                            Price = 0.50M,
                            Category = tractors,
                            Image = "utility-tractor.jpg"
                        },
                        new Product
                        {
                            Name = "Apple seeds",
                            Slug = "apple-seeds",
                            Description = "Juicy apple seeds",
                            Price = 5.99M,
                            Category = seeds,
                            Image = "apple-seeds.jpg"
                        },
                        new Product
                        {
                            Name = "Soybean-Seeds",
                            Slug = "soybean-seeds",
                            Description = "Best soybean seeds",
                            Price = 7.99M,
                            Category = seeds,
                            Image = "soybean-seeds.jpg"
                        }
                );

                context.SaveChanges();
            }
        }
    }
}