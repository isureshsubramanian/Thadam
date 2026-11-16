using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Thadam.Api.Security;
using Thadam.Audit;
using Thadam.Store.Queries;

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

        // Wrong passwords are limited by the sign-in gate (the collector, when installed), not
        // by a shared rate limit that another local program could keep full (ADR-015).
        api.MapPost("/session", SignInAsync)
            .RequireCsrf()
            .Validate<SignInRequest, SignInValidator>();

        api.MapDelete("/session", SignOutAsync)
            .RequireAuthorization()
            .RequireCsrf();
    }

    private static async Task<IResult> SignInAsync(
        SignInRequest body, HttpContext http, SignInGate gate, CancellationToken ct)
    {
        var result = await gate.SignInAsync(body.Password, ct).ConfigureAwait(false);
        switch (result.Status)
        {
            case SignInStatus.SignedIn:
                var identity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.Name, Environment.UserName), new Claim(SignInGate.SessionClaim, result.Session!)],
                    CookieAuthenticationDefaults.AuthenticationScheme);
                await http.SignInAsync(new ClaimsPrincipal(identity)).ConfigureAwait(false);
                return Results.NoContent();
            case SignInStatus.NoPassword:
                return Results.Json(new { errors = NoPassword }, statusCode: StatusCodes.Status409Conflict);
            case SignInStatus.Wait:
                http.Response.Headers.RetryAfter = result.RetryAfter.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return Results.Json(new { errors = Wait, retryAfter = result.RetryAfter }, statusCode: StatusCodes.Status429TooManyRequests);
            default:
                return Results.Unauthorized();
        }
    }

    private static readonly string[] NoPassword = ["no_password"];
    private static readonly string[] Wait = ["wait"];

    private static async Task<IResult> SignOutAsync(HttpContext http, AuditLog audit, StoreQueries queries, CancellationToken ct)
    {
        var session = SignInGate.Session(http.User);
        await http.SignOutAsync().ConfigureAwait(false);
        // Nothing of the lists is kept after the person leaves (ADR-016 Decision 3).
        queries.ClearLists();
        await audit.SignOutAsync(session, ct).ConfigureAwait(false);
        return Results.NoContent();
    }
}
