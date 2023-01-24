using System;
using System.Runtime.InteropServices;

namespace Petrsnd.TacacsPlusCore
{
    public enum TacacsType : byte
    {
        Authentication = 0x01,
        Authorization = 0x02,
        Accounting = 0x03
    }

    [Flags]
    public enum TacacsFlags : byte
    {
        Encrypted = 0x00,
        Unencrypted = 0x01,
        SingleConnectionMode = 0x04,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TacacsHeader
    {
        public byte Version;
        public TacacsType Type;
        public byte SequenceNumber;
        public TacacsFlags Flags;
        public int SessionId;
        public int Length;
    }

    public static class TacacsHeaderExtensions
    {
        private const int VersionLengthBits = 4;
        private const byte MajorVersionMask = 0xF0;
        private const byte MinorVersionMask = 0x0F;
        public const byte DefaultVersion = (0xC << VersionLengthBits) + 0x00;
        public const byte VersionOne = (0xC << VersionLengthBits) + 0x01;

        public static int MajorVersion(this TacacsHeader header)
        {
            return (header.Version & MajorVersionMask) >> VersionLengthBits;
        }

        public static int MinorVersion(this TacacsHeader header)
        {
            return header.Version & MinorVersionMask;
        }
    }

    public enum TacacsAction : byte
    {
        Login = 0x01,
        ChangePassword = 0x02,
        SendPassword = 0x03, // Deprecated
        SendAuthentication = 0x04
    }

    public enum TacacsAuthenticationType : byte
    {
        Ascii = 0x01,
        Pap = 0x02,
        Chap = 0x03,
        Arap = 0x04, // Legacy (see 2020 ietf draft)
        MsChap = 0x05,
        MsChapV2 = 0x06
    }

    public enum TacacsAuthenticationService : byte
    {
        None = 0x00,
        Login = 0x01,
        Enable = 0x02,
        Ppp = 0x03, // Legacy (see 2020 ietf draft)
        Arap = 0x04, // Legacy (see 2020 ietf draft)
        Pt = 0x05, // Legacy (see 2020 ietf draft)
        Rcmd = 0x06, // Legacy (see 2020 ietf draft)
        X25 = 0x07, // Legacy (see 2020 ietf draft)
        Nasi = 0x08, // Legacy (see 2020 ietf draft)
        FwProxy = 0x09 // Legacy (see 2020 ietf draft)
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TacacsAuthenticationRequestHeader
    {
        public TacacsAction Action;
        public byte PrivilegeLevel; // 0 - 15
        public TacacsAuthenticationType AuthenticationType;
        public TacacsAuthenticationService Service;
        public byte UserLength;
        public byte PortLength;
        public byte RemoteLength;
        public byte DataLength;
    }

    public enum TacacsAuthenticationStatus : byte
    {
        Pass = 0x01,
        Fail = 0x02,
        GetData = 0x03,
        GetUser = 0x04,
        GetPassword = 0x05,
        Restart = 0x06,
        Error = 0x07,
        Follow = 0x21
    }

    [Flags]
    public enum TacacsAuthenticationReplyFlags : byte
    {
        NoEcho = 0x01
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TacacsAuthenticationReplyHeader
    {
        public TacacsAuthenticationStatus Status;
        public TacacsAuthenticationReplyFlags Flags;
        public short ServerMessageLength;
        public short DataLength;
    }

    [Flags]
    public enum TacacsAuthenticationContinueFlags : byte
    {
        Abort = 0x01
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TacacsAuthenticationContinueHeader
    {
        public short UserMessageLength;
        public short DataLength;
        public TacacsAuthenticationContinueFlags Flags;
    }
}
