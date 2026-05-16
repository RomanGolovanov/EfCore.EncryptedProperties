namespace EfCore.EncryptedProperties.ApiSample;

public record CreateCustomerRequest(
    string Name,
    string Email,
    DateTime DateOfBirth,
    string SecretNotes,
    int LoyaltyPoints);

public record UpdateCustomerRequest(
    string? Name,
    string? Email,
    DateTime? DateOfBirth,
    string? SecretNotes,
    int? LoyaltyPoints);

public record CustomerResponse(
    Guid Id,
    string Name,
    string Email,
    DateTime DateOfBirth,
    string SecretNotes,
    int LoyaltyPoints);
