using FluentValidation;
using Microsoft.AspNetCore.Antiforgery;

namespace Thadam.Api.Endpoints;

/// <summary>Input checks at the boundary (ADR-008 Decision 4).</summary>
public static class Validation
{
    /// <summary>400 naming the failing fields, never their values.</summary>
    public static IResult Invalid(IEnumerable<string> fields) =>
        Results.Json(new { errors = fields.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray() },
            statusCode: StatusCodes.Status400BadRequest);

    /// <summary>Validates the endpoint's <typeparamref name="T"/> argument with <typeparamref name="TValidator"/>.</summary>
    public static RouteHandlerBuilder Validate<T, TValidator>(this RouteHandlerBuilder b)
        where TValidator : AbstractValidator<T>, new()
    {
        var validator = new TValidator();
        return b.AddEndpointFilter(async (ctx, next) =>
        {
            var arg = ctx.Arguments.OfType<T>().FirstOrDefault();
            if (arg is null)
            {
                return Invalid(["body"]);
            }
            var result = await validator.ValidateAsync(arg, ctx.HttpContext.RequestAborted).ConfigureAwait(false);
            return result.IsValid
                ? await next(ctx).ConfigureAwait(false)
                : Invalid(result.Errors.Select(e => JsonName(e.PropertyName)));
        });
    }

    /// <summary>Writes need the antiforgery token as well as the cookie (ADR-008 Decision 2).</summary>
    public static RouteHandlerBuilder RequireCsrf(this RouteHandlerBuilder b) =>
        b.AddEndpointFilter(async (ctx, next) =>
        {
            var af = ctx.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
            if (!await af.IsRequestValidAsync(ctx.HttpContext).ConfigureAwait(false))
            {
                return Invalid(["antiforgery"]);
            }
            return await next(ctx).ConfigureAwait(false);
        });

    private static string JsonName(string property) =>
        property.Length == 0 ? property : char.ToLowerInvariant(property[0]) + property[1..];
}
