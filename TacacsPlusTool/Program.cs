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
                var client = new TacacsPlusClient(opts.Server, 49, opts.SharedSecret.ToSecureString(), opts.Timeout);

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
                    case "NONE":
                        service = TacacsAuthenticationService.None;
                        break;
                    case "LOGIN":
                        service = TacacsAuthenticationService.Login;
                        break;
                    case "ENABLE":
                        service = TacacsAuthenticationService.Enable;
                        break;
                    default:
                        throw new Exception($"Unrecognized authentication service {opts.Service}");
                }

                if (client.Authenticate(type, service, opts.Username, opts.Password.ToSecureString()))
                {
                    Console.WriteLine("Authentication SUCCESS!");
                }
                else
                {
                    Console.WriteLine("Authentication FAILED!");
                }
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
