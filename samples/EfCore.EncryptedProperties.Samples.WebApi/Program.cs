using EfCore.EncryptedProperties.ApiSample;
using EfCore.EncryptedProperties.Extensions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("Default")!;
var rsaKeyFile = builder.Configuration["Encryption:RsaKeyFile"]!;
var rsaKeyId = builder.Configuration["Encryption:RsaKeyId"]!;

builder.Services.AddEncryptedProperties(cfg =>
{
    cfg.WithFileRsaKeyProvider(rsaKeyFile, rsaKeyId);
    cfg.WithDatabaseKeyChain(SqlClientFactory.Instance, connectionString);
    cfg.WithKeyChainPreloadOnStartup();
});

builder.Services.AddDbContext<ApiSampleDbContext>((sp, options) =>
{
    options.UseSqlServer(connectionString);
    options.UseEncryptedProperties(sp);
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

await using (var scope = app.Services.CreateAsyncScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApiSampleDbContext>();
    await db.Database.EnsureCreatedAsync();
}

// POST /customers
app.MapPost("/customers", async (CreateCustomerRequest req, ApiSampleDbContext db) =>
{
    var customer = new Customer
    {
        Id = Guid.NewGuid(),
        Name = req.Name,
        Email = req.Email,
        DateOfBirth = req.DateOfBirth,
        SecretNotes = req.SecretNotes,
        LoyaltyPoints = req.LoyaltyPoints
    };
    db.Customers.Add(customer);
    await db.SaveChangesAsync();
    return Results.Created($"/customers/{customer.Id}", await ToResponse(customer));
});

// GET /customers
app.MapGet("/customers", async (ApiSampleDbContext db) =>
{
    var customers = await db.Customers.AsNoTracking().ToListAsync();
    var responses = new List<CustomerResponse>(customers.Count);
    foreach (var c in customers)
        responses.Add(await ToResponse(c));
    return responses;
});

// GET /customers/{id}
app.MapGet("/customers/{id:guid}", async (Guid id, ApiSampleDbContext db) =>
{
    var customer = await db.Customers.FindAsync(id);
    return customer is null ? Results.NotFound() : Results.Ok(await ToResponse(customer));
});

// PUT /customers/{id}
app.MapPut("/customers/{id:guid}", async (Guid id, UpdateCustomerRequest req, ApiSampleDbContext db) =>
{
    var customer = await db.Customers.FindAsync(id);
    if (customer is null) return Results.NotFound();

    if (req.Name is not null) customer.Name = req.Name;
    if (req.Email is not null) customer.Email = req.Email;
    if (req.DateOfBirth is not null) customer.DateOfBirth = req.DateOfBirth.Value;
    if (req.SecretNotes is not null) customer.SecretNotes = req.SecretNotes;
    if (req.LoyaltyPoints is not null) customer.LoyaltyPoints = req.LoyaltyPoints.Value;

    await db.SaveChangesAsync();
    return Results.Ok(await ToResponse(customer));
});

// DELETE /customers/{id}
app.MapDelete("/customers/{id:guid}", async (Guid id, ApiSampleDbContext db) =>
{
    var customer = await db.Customers.FindAsync(id);
    if (customer is null) return Results.NotFound();

    db.Customers.Remove(customer);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

static async Task<CustomerResponse> ToResponse(Customer c)
{
    var loyaltyPoints = await c.LoyaltyPoints.GetDecryptedValueAsync();

    return new CustomerResponse(
        c.Id,
        c.Name,
        c.Email,
        c.DateOfBirth,
        await c.SecretNotes.GetDecryptedValueAsync() ?? string.Empty,
        loyaltyPoints);
}
