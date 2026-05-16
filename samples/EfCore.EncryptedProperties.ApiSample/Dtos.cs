namespace EfCore.EncryptedProperties.ApiSample;

public record CreateCustomerRequest(string Name, string Email, string SecretNotes);

public record UpdateCustomerRequest(string? Name, string? Email, string? SecretNotes);

public record CustomerResponse(Guid Id, string Name, string Email, string SecretNotes);
