// -----------------------------------------------------------------------------
// <copyright file="Connection.cs" company="Paul C. Roberts">
//  Copyright 2012 Paul C. Roberts
//
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file 
//  except in compliance with the License. You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software distributed under the 
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
//  either express or implied. See the License for the specific language governing permissions and 
//  limitations under the License.
// </copyright>
// -----------------------------------------------------------------------------

namespace PollRobots.OmotVnc.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
#if !NETFX_CORE
    using System.Security.Cryptography;
#endif
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
#if NETFX_CORE
    using Windows.Networking.Sockets;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Core;
#endif

    /// <summary>The service that manages a connection to a VNC server.</summary>
    public sealed class Connection : ConnectionOperations, IDisposable
    {
        private const int VNC_SECURITY_PROTOCOL_INVALID = 0;
        private const int VNC_SECURITY_PROTOCOL_NONE = 1;
        private const int VNC_SECURITY_PROTOCOL_VNCAUTHENTICATION = 2;

        /// <summary>The first 4 characters of the protocol version packet.</summary>
        private const string ProtocolVersionStart = "RFB ";

        /// <summary>The protocol major version supported.</summary>
        private const int ProtocolMajorVersion = 3;

        /// <summary>The protocol minor version supported.</summary>
        private const int ProtocolMinorVersion = 8;

        /// <summary>The client protocol version packet.</summary>
        private const string ClientProtocolVersion = "RFB 003.008\n";

        /// <summary>The supported security protocols</summary>
        private static readonly byte[] SecurityProtocols = { VNC_SECURITY_PROTOCOL_VNCAUTHENTICATION, VNC_SECURITY_PROTOCOL_NONE };

        /// <summary>The default timeout when talking to a server</summary>
        /// <remarks>THis presupposes that the service is close in network 
        /// terms.</remarks>
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);

        /// <summary>Lookup table for reversing nibble values (used as part of
        /// the password encryption)</summary>
        private static readonly byte[] ReverseNibble = { 0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE, 0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF };

        /// <summary>Lock used for exclusive async access to the stream.</summary>
        private ExclusiveLock exclusiveLock = new ExclusiveLock();

        /// <summary>The connection input stream.</summary>
        private Stream readStream;

        /// <summary>The connection output stream.</summary>
        private Stream writeStream;

        /// <summary>The pixel format being used.</summary>
        private PixelFormat pixelFormat;

        /// <summary>The current connection state.</summary>
        private ConnectionState state;

        /// <summary>The action to take on a rectangle update.</summary>
        private Action<Rectangle> onRectangle;

        /// <summary>The action to take on a state change.</summary>
        private Action<ConnectionState> onConnectionStateChange;

        /// <summary>The action to take on an exception.</summary>
        private Action<Exception> onException;

        /// <summary>The number of pending update responses.</summary>
        private int pendingUpdateResponse;

        /// <summary>The last time a set pointer message was sent.</summary>
        private DateTime lastSetPointer;

        /// <summary>
        /// Initializes a new instance of the <see cref="Connection"/> class.
        /// </summary>
        /// <param name="readStream">The stream for reading.</param>
        /// <param name="writeStream">The stream for writing.</param>
        /// <param name="rectangleAction">The action to take when a rectangle is received.</param>
        /// <param name="connectionStateChangeAction">The action to take on a state change.</param>
        /// <param name="exceptionAction">The action to take on an exception.</param>
        private Connection(Stream readStream, Stream writeStream, Action<Rectangle> rectangleAction, Action<ConnectionState> connectionStateChangeAction, Action<Exception> exceptionAction)
        {
            this.readStream = readStream;
            this.writeStream = writeStream;
            onRectangle = rectangleAction ?? (_ => { });
            onConnectionStateChange = connectionStateChangeAction ?? (_ => { });
            onException = exceptionAction ?? (_ => { });
        }

        /// <summary>
        /// Gets a value indicating whether a password is required.
        /// </summary>
        public bool RequiresPassword { get; private set; }

        /// <summary>
        /// Gets the current connection state of this service.
        /// </summary>
        public ConnectionState ConnectionState
        {
            get
            {
                return state;
            }

            private set
            {
                if (value != state)
                {
                    state = value;
                    onConnectionStateChange(state);
                }
            }
        }

        /// <summary>
        /// Gets the screen Width.
        /// </summary>
        public int Width { get; private set; }

        /// <summary>
        /// Gets the screen Height.
        /// </summary>
        public int Height { get; private set; }

        /// <summary>
        /// Gets the connection Name.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the connection is initialized.
        /// </summary>
        public bool Initialized { get; private set; }

#if NETFX_CORE
        /// <summary>Create an instance of the <see cref="Connection"/> service.
        /// </summary>
        /// <param name="streamSocket">The connection stream.</param>
        /// <param name="onRectangle">The action to take when a rectangle is received.</param>
        /// <param name="onStateChange">The action to take on a state change.</param>
        /// <param name="onException">The action to take on an exception.</param>
        /// <returns>The operations instance used to communicate with the service.</returns>
        public static ConnectionOperations CreateFromStreamSocket(StreamSocket streamSocket, Action<Rectangle> onRectangle, Action<ConnectionState> onStateChange, Action<Exception> onException)
        {
            var readStream = streamSocket.InputStream.AsStreamForRead();
            var writeStream = streamSocket.OutputStream.AsStreamForWrite();
            var connection = new Connection(readStream, writeStream, onRectangle, onStateChange, onException);

            connection.Init();

            return connection;
        }
#else
        /// <summary>Create an instance of the <see cref="Connection"/> service.
        /// </summary>
        /// <param name="stream">The connection stream.</param>
        /// <param name="onRectangle">The action to take when a rectangle is received.</param>
        /// <param name="onStateChange">The action to take on a state change.</param>
        /// <param name="onException">The action to take on an exception.</param>
        /// <returns>The operations instance used to communicate with the service.</returns>
        public static ConnectionOperations CreateFromStream(Stream stream, Action<Rectangle> onRectangle, Action<ConnectionState> onStateChange, Action<Exception> onException)
        {
            var connection = new Connection(stream, stream, onRectangle, onStateChange, onException);

            connection.Init();

            return connection;
        }
#endif

        /// <summary>Implements the Dispose method.</summary>
        public void Dispose()
        {
            using (var old = readStream)
            {
                readStream = null;
                ConnectionState = ConnectionState.Disconnected;
            }
        }

        /// <summary>Handles the shutdown message.</summary>
        /// <returns>An async task.</returns>
        public override async Task ShutdownAsync()
        {
            try
            {
                using (await exclusiveLock.Enter())
                {
                    Dispose();
                    await Task.Yield();
                }
            }
            catch (Exception e)
            {
                onException(e);
            }
        }

        /// <summary>Handles the start message; this starts the process of
        /// waiting for server packets.</summary>
        /// <returns>An async task.</returns>
        public override async Task StartAsync()
        {
            try
            {
                using (await exclusiveLock.Enter())
                {
                    if (!Initialized)
                    {
                        throw new InvalidOperationException("Unable to start");
                    }
                }
            }
            catch (Exception e)
            {
                onException(e);
                throw;
            }

            await Task.Yield();

            var ignored = Task.Run(() => WaitForServerPacket());
        }

        /// <summary>Handles the update message; this sends an update request
        /// to the server.</summary>
        /// <param name="refresh">Does this update report a complete refresh.</param>
        /// <returns>An async task.</returns>
        public override async Task UpdateAsync(bool refresh)
        {
            using (await exclusiveLock.Enter())
            {
                if (pendingUpdateResponse > 0 && !refresh)
                {
                    return;
                }

                try
                {
                    var packet = new byte[10];

                    packet[0] = 3;
                    packet[1] = (byte)(refresh ? 0 : 1);

                    packet[6] = (byte)((Width >> 8) & 0xFF);
                    packet[7] = (byte)(Width & 0xFF);
                    packet[8] = (byte)((Height >> 8) & 0xFF);
                    packet[9] = (byte)(Height & 0xFF);

                    using (var cancellation = new CancellationTokenSource())
                    {
                        cancellation.CancelAfter(DefaultTimeout);

                        Interlocked.Increment(ref pendingUpdateResponse);

                        await writeStream.WriteAsync(packet, 0, packet.Length, cancellation.Token);
                        await writeStream.FlushAsync();
                    }
                }
                catch (Exception e)
                {
                    Disconnected(e);
                }
            }
        }

        /// <summary>Handles the set pointer message, this sends the pointer 
        /// position and button state to the server.
        /// </summary>
        /// <remarks>Setting the pointer position also causes an update.
        /// </remarks>
        /// <param name="buttons">The current button state.</param>
        /// <param name="x">The pointer x coordinate.</param>
        /// <param name="y">The pointer y coordinate.</param>
        /// <param name="isHighPriority">Indicates whether this request is high-priority. High priority requests are never ignored.</param>
        /// <returns>An async task.</returns>
        public override async Task SetPointerAsync(int buttons, int x, int y, bool isHighPriority)
        {
            var now = DateTime.UtcNow;

            if (!isHighPriority && (now - lastSetPointer).TotalMilliseconds < 50)
            {
                return;
            }

            using (await exclusiveLock.Enter())
            {
                try
                {
                    var packet = new byte[6];

                    packet[0] = 5;
                    packet[1] = (byte)buttons;
                    packet[2] = (byte)((x >> 8) & 0xFF);
                    packet[3] = (byte)(x & 0xFF);
                    packet[4] = (byte)((y >> 8) & 0xFF);
                    packet[5] = (byte)(y & 0xFF);

                    using (var cancellation = new CancellationTokenSource())
                    {
                        cancellation.CancelAfter(DefaultTimeout);

                        lastSetPointer = now;

                        await writeStream.WriteAsync(packet, 0, packet.Length, cancellation.Token);
                        await writeStream.FlushAsync();
                    }

                    var ignored = Task.Run(() => UpdateAsync(false));
                }
                catch (Exception e)
                {
                    Disconnected(e);
                }
            }
        }

        /// <summary>Handles the send key message, this sends key state change
        /// data to the server.</summary>
        /// <remarks>If the update flag is set in the message, this triggers an
        /// update.</remarks>
        /// <param name="isDown">Indicates whether the key is down.</param>
        /// <param name="key">The key that changed.</param>
        /// <param name="update">Indicates whether this should trigger an update</param>
        /// <returns>An async task.</returns>
        public override async Task SendKeyAsync(bool isDown, uint key, bool update)
        {
            using (await exclusiveLock.Enter())
            {
                try
                {
                    var packet = new byte[8];

                    packet[0] = 4;
                    packet[1] = (byte)(isDown ? 1 : 0);

                    packet[4] = (byte)((key >> 24) & 0xFF);
                    packet[5] = (byte)((key >> 16) & 0xFF);
                    packet[6] = (byte)((key >> 8) & 0xFF);
                    packet[7] = (byte)(key & 0xFF);

                    await writeStream.WriteAsync(packet, 0, packet.Length);
                    await writeStream.FlushAsync();

                    if (update)
                    {
                        var ignore = Task.Run(() => UpdateAsync(false));
                    }
                }
                catch (Exception e)
                {
                    Disconnected(e);
                }
            }
        }

        /// <summary>Handles a get connection info message.</summary>
        /// <returns>The current connection info.</returns>
        public override ConnectionInfo GetConnectionInfo()
        {
            return new ConnectionInfo
            {
                Width = Width,
                Height = Height,
                Name = Name
            };
        }

        /// <summary>Performs the handshaking process.</summary>
        /// <returns>A value indicating whether a password is required.</returns>
        public override async Task<bool> HandshakeAsync()
        {
            const int VNC_PROTOCOL_VERSION_LENGTH = 12;
            const int VNC_SECURITY_TYPES_ALLOWED_HEADER = 1;

            using (await exclusiveLock.Enter())
            {
                var packet = new byte[VNC_PROTOCOL_VERSION_LENGTH];

                if (ConnectionState != ConnectionState.Disconnected)
                {
                    throw new InvalidOperationException();
                }

                ConnectionState = ConnectionState.Handshaking;

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(packet, cancellation.Token);
                }

                var versionString = Encoding.UTF8.GetString(packet, 0, packet.Length);

                if (!versionString.StartsWith(ProtocolVersionStart, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Expecting: " + ProtocolVersionStart);
                }

                int major;
                int minor;
                if (!int.TryParse(versionString.Substring(4, 3), out major)
                    ||
                    !int.TryParse(versionString.Substring(8, 3), out minor))
                {
                    throw new InvalidDataException("Cannot parse protocol version");
                }

                if (major < ProtocolMajorVersion && minor < ProtocolMinorVersion)
                {
                    throw new InvalidDataException("Server protocol version is not supported");
                }

                packet = Encoding.UTF8.GetBytes(ClientProtocolVersion);

                await writeStream.WriteAsync(packet, 0, packet.Length);
                await writeStream.FlushAsync();

                var numberOfsecurityTypesPacket =  new byte[VNC_SECURITY_TYPES_ALLOWED_HEADER];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(numberOfsecurityTypesPacket, cancellation.Token);
                }

                int numberOfSecurityTypes = numberOfsecurityTypesPacket[0];

                if (numberOfSecurityTypes == 0)
                {
                    await ProcessConnectionError("Protocol version not supported.");
                    return true;
                }

                var allowedSecurityTypesPacket = new byte[numberOfSecurityTypes];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(allowedSecurityTypesPacket, cancellation.Token);
                }

                byte securityType = allowedSecurityTypesPacket
                    .FirstOrDefault(st => SecurityProtocols.Contains(st));

                if (securityType == 0)
                {
                    throw new InvalidDataException("Unable to negotiate a security protocol.");
                }

                writeStream.WriteByte(securityType);

                await writeStream.FlushAsync();

                switch (securityType)
                {
                    case VNC_SECURITY_PROTOCOL_NONE:
                        RequiresPassword = false;
                        break;
                    case VNC_SECURITY_PROTOCOL_VNCAUTHENTICATION:
                        RequiresPassword = true;
                        break;
                    default:
                        throw new InvalidOperationException();
                }

                return RequiresPassword;
            }
        }

        /// <summary>Send password to the server</summary>
        /// <param name="password">The password to send</param>
        /// <returns>An async task.</returns>
        public override async Task SendPasswordAsync(string password)
        {
            const int VNC_SECURITY_NONCE_LENGTH = 16;

            const int VNC_SECURITY_RESULT_LENGTH = 4;

            const int VNC_SECURITY_RESULT_OK = 0;
            const int VNC_SECURITY_RESULT_FAILED = 1;

            using (await exclusiveLock.Enter())
            {
                if (ConnectionState != ConnectionState.Handshaking || RequiresPassword == false)
                {
                    throw new InvalidOperationException();
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentNullException(nameof(password));
                }

                ConnectionState = ConnectionState.SendingPassword;

                byte[] nonce = new byte[VNC_SECURITY_NONCE_LENGTH];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(nonce, cancellation.Token);
                }

#if NETFX_CORE
                var des = SymmetricKeyAlgorithmProvider.OpenAlgorithm("DES_ECB");
                var key = new byte[des.BlockLength];

                Encoding.UTF8.GetBytes(password, 0, Math.Min(password.Length, key.Length), key, 0);
                ReverseByteArrayElements(key);

                var cryptoKey = des.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
                var encryptedResponse = CryptographicEngine.Encrypt(cryptoKey, CryptographicBuffer.CreateFromByteArray(nonce), null);

                byte[] response;
                CryptographicBuffer.CopyToByteArray(encryptedResponse, out response);
#else
                var des = DES.Create();
                var key = new byte[des.KeySize / 8];

                Encoding.ASCII.GetBytes(password, 0, Math.Min(password.Length, key.Length), key, 0);

                ReverseByteArrayElements(key);

                des.Key = key;

                des.Mode = CipherMode.ECB;
                var encryptor = des.CreateEncryptor();

                var response = new byte[nonce.Length];

                encryptor.TransformBlock(nonce, 0, nonce.Length, response, 0);
#endif
                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await writeStream.WriteAsync(response, 0, response.Length, cancellation.Token);
                    await writeStream.FlushAsync();
                }

                var securityResultPacket = new byte[VNC_SECURITY_RESULT_LENGTH];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(securityResultPacket, cancellation.Token);
                }

                int securityResult = ConvertBigEndianU32(securityResultPacket);

                if (securityResult != VNC_SECURITY_RESULT_OK)
                {
                    await ProcessConnectionError("Invalid password");

                    return;
                }
            }
        }

        /// <summary>Initialize the connection.</summary>
        /// <param name="shareDesktop">
        /// Shared-flag is non-zero (true) if the server should try to share the 
        /// desktop by leaving other clients connected, and zero(false) if it
        /// should give exclusive access to this client by disconnecting all
        /// other clients.
        /// </param>
        /// <returns>An async task</returns>
        public override async Task InitializeAsync(bool shareDesktop)
        {
            const int VNC_SERVERINIT_HEADER_LENGTH = 24;

            using (await exclusiveLock.Enter())
            {
                if ((RequiresPassword && ConnectionState != ConnectionState.SendingPassword)
                    || 
                    (RequiresPassword == false && ConnectionState != ConnectionState.Handshaking))
                {
                    throw new InvalidOperationException();
                }

                ConnectionState = ConnectionState.Initializing;

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    var share = new byte[] { (byte)(shareDesktop ? 1 : 0) };
                    await writeStream.WriteAsync(share, 0, 1, cancellation.Token);
                    await writeStream.FlushAsync();
                }

                var packet = new byte[VNC_SERVERINIT_HEADER_LENGTH];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(packet, cancellation.Token);
                }

                Width = (packet[0] << 8) | packet[1];
                Height = (packet[2] << 8) | packet[3];

                pixelFormat = PixelFormat.FromServerInit(packet);

                byte[] requestNamePacket = new byte[ConvertBigEndianU32(packet, 20)];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(requestNamePacket, cancellation.Token);
                }

                Name = Encoding.UTF8.GetString(requestNamePacket, 0, requestNamePacket.Length);

                Initialized = true;

                ConnectionState = ConnectionState.Connected;
            }
        }

        /// <summary>Reverse the order of the bits in the elements of a byte 
        /// array</summary>
        /// <param name="input">The byte array to modify, this is modified in 
        /// place</param>
        private static void ReverseByteArrayElements(byte[] input)
        {
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = ReverseBits(input[i]);
            }
        }

        /// <summary>Reverse the bits in a byte</summary>
        /// <param name="input">The input byte</param>
        /// <returns>A byte with bits in the reverse order to the input</returns>
        private static byte ReverseBits(byte input)
        {
            var high = (input >> 4) & 0x0F;
            var low = input & 0x0F;

            return (byte)((ReverseNibble[low] << 4) | ReverseNibble[high]);
        }

        /// <summary>Converts a big endian byte sequence to a 32-bit 
        /// integer.</summary>
        /// <param name="buffer">The byte array containing the sequence</param>
        /// <param name="offset">The offset at which the integer starts.</param>
        /// <returns>The integer representation</returns>
        private static int ConvertBigEndianU32(byte[] buffer, int offset = 0)
        {
            return buffer[offset] << 24 | buffer[offset + 1] << 16 | buffer[offset + 2] << 8 | buffer[offset + 3];
        }

        /// <summary>Initializes the message receivers</summary>
        private void Init()
        {
        }

        /// <summary>Waits for a server packet, reads the packet and dispatches
        /// it appropriately.</summary>
        /// <returns>A CCR task enumerator</returns>
        private async Task WaitForServerPacket()
        {
            const byte VNC_SERVERTOCLIENT_FRAMEBUFFERUPDATE = 0;
            const byte VNC_SERVERTOCLIENT_SETCOLORMAPENTRIES = 1;
            const byte VNC_SERVERTOCLIENT_BELL = 2;
            const byte VNC_SERVERTOCLIENT_SERVERCUTTEXT = 3;

            while (true)
            {
                byte[] serverMessagePacket = new byte[1];

                var read = await readStream.ReadAsync(serverMessagePacket, 0, serverMessagePacket.Length);

                if (read != serverMessagePacket.Length)
                {
                    RaiseProtocolException("Unable to read packet id", new InvalidDataException());
                }

                switch (serverMessagePacket[0])
                {
                    case VNC_SERVERTOCLIENT_FRAMEBUFFERUPDATE:
                        await ReadFramebufferUpdate();
                        Interlocked.Decrement(ref pendingUpdateResponse);
                        break;

                    case VNC_SERVERTOCLIENT_SETCOLORMAPENTRIES:
                        SetColourMapEntries();
                        break;

                    case VNC_SERVERTOCLIENT_BELL:
                        Bell();
                        break;

                    case VNC_SERVERTOCLIENT_SERVERCUTTEXT:
                        ServerCutText();
                        break;
                }
            }
        }

        /// <summary>Reads an update to the frame buffer from the server.</summary>
        /// <returns>A CCR task enumerator</returns>
        private async Task ReadFramebufferUpdate()
        {
            try
            {
                var packet = new byte[3];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(packet, cancellation.Token);
                }

                var count = (packet[1] << 8) | packet[2];

                for (var i = 0; i < count; i++)
                {
                    await ReadRectangle();
                }
            }
            catch (Exception e)
            {
                Disconnected(e);
            }
        }

        /// <summary>Reads a packet from the read stream.</summary>
        /// <param name="buffer">The buffer to fill from the network</param>
        /// <param name="cancelToken">A cancellation token.</param>
        /// <returns>An async task.</returns>
        private async Task ReadPacketAsync(byte[] buffer, CancellationToken cancelToken)
        {
            await readStream.ReadAsync(buffer, 0, buffer.Length, cancelToken);
        }

        /// <summary>Read an update rectangle from the server.</summary>
        /// <returns>A CCR task enumerator</returns>
        private async Task ReadRectangle()
        {
            const int VNC_ENCODINGS_RAW = 0;

            var packet = new byte[12];

            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.CancelAfter(DefaultTimeout);

                await ReadPacketAsync(packet, cancellation.Token);
            }

            int left = (packet[0] << 8) | packet[1];
            int top = (packet[2] << 8) | packet[3];
            int width = (packet[4] << 8) | packet[5];
            int height = (packet[6] << 8) | packet[7];

            int encoding = ConvertBigEndianU32(packet, 8);

            if(encoding == VNC_ENCODINGS_RAW)
            {
                //TODO: for now we only support Raw encoding, see https://tools.ietf.org/html/rfc6143#section-7.7
                //throw new InvalidDataException("Unexpected encoding.");

                byte[] pixelBuffer = new byte[width * height * pixelFormat.BytesPerPixel];

                var rectangle = new Rectangle(left, top, width, height, pixelBuffer);

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);

                    await ReadPacketAsync(pixelBuffer, cancellation.Token);
                }

                onRectangle(rectangle);
            }

            
        }

        /// <summary>Setting the palette is not implemented.</summary>
        private void SetColourMapEntries()
        {
            RaiseProtocolException("SetColourMapEntries", new NotImplementedException());
        }

        /// <summary>Sounding the bell is not implemented.</summary>
        private void Bell()
        {
            FireBell();
        }

        /// <summary>Handling server cut text operations is not implemented</summary>
        private void ServerCutText()
        {
            RaiseProtocolException("ServerCutText", new NotImplementedException());
        }

        /// <summary>Called when an exception occurs that disconnects the 
        /// stream.</summary>
        /// <param name="exception">The exception that reports the 
        /// disconnection.</param>
        private void Disconnected(Exception exception)
        {
            state = ConnectionState.Disconnected;

            onException(exception);
        }

        /// <summary>Handles a connection error reported from the server.</summary>
        /// <param name="reason">The error reason.</param>
        /// <returns>A CCR task enumerator</returns>
        private async Task ProcessConnectionError(string reason)
        {
            const int VNC_SECURITYRESULT_REASON_LENGHT = 4;

            var reasonLengthPacket = new byte[VNC_SECURITYRESULT_REASON_LENGHT];

            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.CancelAfter(DefaultTimeout);

                await ReadPacketAsync(reasonLengthPacket, cancellation.Token);
            }

            int length = ConvertBigEndianU32(reasonLengthPacket);

            //TODO: this is kind of weird... we should check it out
            length = Math.Min(Math.Max(1024, length), 0);

            Exception exception;

            if (length > 0)
            {
                reasonLengthPacket = new byte[length];

                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.CancelAfter(DefaultTimeout);
                    await ReadPacketAsync(reasonLengthPacket, cancellation.Token);
                }

                exception = new Exception(reason + Encoding.UTF8.GetString(reasonLengthPacket, 0, reasonLengthPacket.Length));
            }
            else
            {
                exception = new Exception(reason);
            }

            Disconnected(exception);

            throw exception;
        }

        /// <summary>Called to process unhandled exception in the protocol.</summary>
        /// <param name="message">The reason for the exception.</param>
        /// <param name="exception">The exception causing the disconnection.</param>
        private void RaiseProtocolException(string message, Exception exception)
        {
            Disconnected(new Exception(message, exception));
        }
    }
}