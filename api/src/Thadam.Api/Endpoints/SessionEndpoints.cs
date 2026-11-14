using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Thadam.Api.Security;
using Thadam.Audit;

namespace Thadam.Api.Endpoints;

public sealed record SignInRequest(string Password);

public sealed class SignInValidator : AbstractValidator<SignInRequest>
{
    public SignInValidator() =>
        RuleFor(r => r.Password).NotEmpty().MaximumLength(Credentials.MaxLength);
}

/// <summary>Sign-in and sign-out (ADR-008 Decision 2). Every attempt is audited.</summary>
public static class SessionEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);

        // The token for the next write. Anonymous, because sign-in itself is a write.
        api.MapGet("/antiforgery", (HttpContext http, IAntiforgery af) =>
            Results.Json(new { token = af.GetAndStoreTokens(http).RequestToken }));

        api.MapPost("/session", SignInAsync)
            .RequireRateLimiting(ApiHost.SignInPolicy)
            .RequireCsrf()
            .Validate<SignInRequest, SignInValidator>();

        api.MapDelete("/session", SignOutAsync)
            .RequireAuthorization()
            .RequireCsrf();
    }

    private static async Task<IResult> SignInAsync(
        SignInRequest body, HttpContext http, ApiOptions options, AuditLog audit, CancellationToken ct)
    {
        var stored = await Credentials.LoadAsync(options.CredentialsPath, ct).ConfigureAwait(false);
        if (stored is null || !Credentials.Verify(body.Password, stored))
        {
            await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Failed, ct).ConfigureAwait(false);
            return Results.Unauthorized();
        }
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, Environment.UserName)], CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(new ClaimsPrincipal(identity)).ConfigureAwait(false);
        await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Succeeded, ct).ConfigureAwait(false);
        return Results.NoContent();
    }

    private static async Task<IResult> SignOutAsync(HttpContext http, AuditLog audit, CancellationToken ct)
    {
        await http.SignOutAsync().ConfigureAwait(false);
        await audit.AppendAsync(AuditAction.SignOut, "", AuditOutcome.Succeeded, ct).ConfigureAwait(false);
        return Results.NoContent();
    }
}
