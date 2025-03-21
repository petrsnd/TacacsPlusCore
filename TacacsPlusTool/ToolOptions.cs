﻿using CommandLine;
using CommandLine.Text;

namespace Petrsnd.TacacsPlusCore.Tool
{
    internal class ToolOptions
    {
        [Option('s', "Server", Required = true,
            HelpText = "IP address or hostname of TACACS+ server")]
        public string Server { get; set; }

        [Option('S', "SharedSecret", Required = true,
            HelpText = "TACACS+ shared secret")]
        public string SharedSecret { get; set; }

        [Option('v', "Service", Required = false, Default = "None",
            HelpText = "TACACS+ service (None, Login, Enable)")]
        public string Service { get; set; }

        [Option('u', "Username", Required = true, SetName = "PasswordSet",
            HelpText = "TACACS+ username to use to authenticate")]
        public string Username { get; set; }

        [Option('p', "Password", Required = true, Default = false,
            HelpText = "TACACS+ password to use to authenticate")]
        public string Password { get; set; }

        [Option('t', "AuthType", Required = true, Default = false,
            HelpText = "TACACS+ authentication protocol (CHAP, MSCHAPv1, MSCHAPv2)")]
        public string AuthType { get; set; }

        [Option('T', "Timeout", Required = false, Default = 3000,
            HelpText = "TACACS+ client timeout in milliseconds")]
        public int Timeout { get; set; }
    }
}
