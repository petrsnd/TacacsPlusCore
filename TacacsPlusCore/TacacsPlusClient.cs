using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Threading;
using Petrsnd.TacacsPlusCore.Utils;

namespace Petrsnd.TacacsPlusCore
{
    public class TacacsPlusClient : IDisposable
    {
        private readonly SecureString _sharedSecret;
        private readonly int _timeout;

        private readonly IPEndPoint _serverIpEndPoint;

        public TacacsPlusClient(string server, int port, SecureString sharedSecret, int timeout = 3000)
        {
            _sharedSecret = sharedSecret.Copy();
            _timeout = timeout;

            if (IPAddress.TryParse(server, out var address))
            {
                _serverIpEndPoint = new IPEndPoint(address, port);
            }
            else
            {
                try
                {
                    var ipHostInfo = Dns.GetHostEntry(server);
                    if (ipHostInfo.AddressList.Length == 0)
                        throw new Exception($"Unable to find server to connect to {server}:{port}");
                    address = ipHostInfo.AddressList[0];
                    _serverIpEndPoint = new IPEndPoint(address, port);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Unable to create client to connect to {server}:{port}", ex);
                }
            }
        }

        public bool Authenticate(TacacsAuthenticationType type, TacacsAuthenticationService service, string user,
            SecureString password)
        {
            if (string.IsNullOrEmpty(user))
                throw new ArgumentException("Must specify a valid user name", nameof(user));
            if (password == null)
                throw new ArgumentException("Must specify a valid password", nameof(password));

            var requestPacket = TacacsPlusProtocol.GetAuthenticationPacket(type, service, user, password, _sharedSecret);
            var responsePacket = SendReceive(requestPacket);

            var responsePayload = ValidateResponseAndGetPayload(responsePacket);

            var authenticationReplyHeader =
                StructConverter.BytesToStruct<TacacsAuthenticationReplyHeader>(responsePayload);
            switch (authenticationReplyHeader.Status)
            {
                case TacacsAuthenticationStatus.Pass:
                    return true;
                case TacacsAuthenticationStatus.Fail:
                    return false;
                case TacacsAuthenticationStatus.Error:
                    var serverMessage =
                        Encoding.UTF8.GetString(responsePayload.Skip(6 /* Authentication Reply Header Size */)
                            .Take(authenticationReplyHeader.ServerMessageLength).ToArray());
                    throw new Exception($"Server responded with an error: {serverMessage}");
                default:
                    throw new Exception($"Unexpected authentication status: {authenticationReplyHeader.Status}");
            }
        }

        private byte[] SendReceive(byte[] requestPacket)
        {
            const int MAX_PACKET_SIZE = 65536;
            using (var client = new Socket(_serverIpEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                client.Connect(_serverIpEndPoint);

                client.SendTimeout = _timeout;
                client.ReceiveTimeout = _timeout;
                var startTime = DateTime.Now;

                _ = client.Send(requestPacket);
                var responseData = new byte[MAX_PACKET_SIZE];
                var responseSize = 0;
                while (responseSize <= 0)
                {
                    responseSize = client.Receive(responseData);
                    if (responseSize == 0)
                    {
                        if (DateTime.Now.Subtract(startTime) > TimeSpan.FromMilliseconds(_timeout))
                            throw new Exception("Timed out waiting for server response;");
                        Thread.Sleep(100);
                    }
                }

                return responseData.Take(responseSize).ToArray();
            }
        }

        private byte[] ValidateResponseAndGetPayload(byte[] responsePacket)
        {
            var responseHeader = StructConverter.BytesToStruct<TacacsHeader>(responsePacket);
            if (responseHeader.Version != 0xc1)
                throw new Exception($"Unexpected response header version: 0x{responseHeader.Version:X}");
            if (responseHeader.Flags != TacacsFlags.Encrypted)
                throw new Exception($"Unexpected response header flags: 0x{responseHeader.Flags:X}");
            if (responseHeader.SequenceNumber % 2 != 0)
                throw new Exception($"Response header sequence number should be odd: 0x{responseHeader.SequenceNumber:X}");
            return GetResponsePayload(responseHeader, responsePacket);
        }

        private byte[] GetResponsePayload(TacacsHeader responseHeader, byte[] responsePacket)
        {
            var responsePayload = responsePacket.Skip(responsePacket.Length - responseHeader.Length).ToArray();
            var pseudoPad = TacacsPlusProtocol.GetPseudoPad(responseHeader, responseHeader.Length, _sharedSecret);
            return TacacsPlusProtocol.XorPseudoPad(responsePayload, pseudoPad);
        }

        public void Dispose()
        {
            _sharedSecret?.Dispose();
        }
    }
}
