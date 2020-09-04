using System;
using System.Collections.Generic;
using CommandLine;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore.Tool
{
    internal class Program
    {
        private static void Execute(ToolOptions opts)
        {
            try
            {
                var client = new TacacsPlusClient(opts.Server, 49, opts.SharedSecret.ToSecureString());

                TacacsAuthenticationType type;
                TacacsAuthenticationService service;
                switch (opts.AuthType.ToUpper())
                {
                    case "CHAP":
                        type = TacacsAuthenticationType.Chap;
                        break;
                    case "MSCHAP":
                    case "MSCHAPV1":
                        type = TacacsAuthenticationType.MsChap;
                        break;
                    case "MSCHAPV2":
                        type = TacacsAuthenticationType.MsChapV2;
                        break;
                    default:
                        throw new Exception($"Unrecognized authentication type {opts.AuthType}");
                }

                switch (opts.Service.ToUpper())
                {
                    case "None":
                        service = TacacsAuthenticationService.None;
                        break;
                    case "Login":
                        service = TacacsAuthenticationService.Login;
                        break;
                    case "Enable":
                        service = TacacsAuthenticationService.Enable;
                        break;
                    default:
                        throw new Exception($"Unrecognized authentication service {opts.AuthType}");
                }

                client.Authenticate(type, service, opts.Username, opts.Password.ToSecureString());

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fatal exception occurred: {ex}");
                Environment.Exit(1);
            }
        }

        private static void HandleParseError(IEnumerable<Error> errors)
        {
            Console.WriteLine("Invalid command line options");
            Console.WriteLine(errors);
            Environment.Exit(1);
        }

        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<ToolOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
