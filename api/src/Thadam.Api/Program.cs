using Thadam.Api;
using Thadam.Api.Security;
using Thadam.Audit;

// thadam-api: the local API and dashboard host (ADR-008).
// Exit codes: 0 done, 1 check failed, 2 usage or setup error. Output carries no paths,
// queries or values.
const string Usage = """
    usage:
      thadam-api run [--store <folder>] [--registry <file>] [--data-dir <folder>] [--port <n>]
      thadam-api set-password [--data-dir <folder>]
      thadam-api verify-audit [--data-dir <folder>]
    """;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};
var command = args.Length == 0 ? "run" : args[0];
var (options, error) = ApiOptions.Parse(args.Skip(1).ToArray());
if (options is null)
{
    await Console.Error.WriteLineAsync($"{error}\n{Usage}");
    return 2;
}
switch (command)
{
    case "run":
        var app = await ApiHost.BuildAsync(options, TimeProvider.System, cts.Token);
        await app.RunAsync(cts.Token);
        return 0;
    case "set-password":
        return await Commands.SetPasswordAsync(options, cts.Token);
    case "verify-audit":
        return await Commands.VerifyAuditAsync(options, cts.Token);
    default:
        await Console.Error.WriteLineAsync(Usage);
        return 2;
}
