using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PollRobots.OmotVncProtocol
{
    internal class RfbProtocol
    {
        private const int DEFAULT_TIMEOUT = 5000;

        private const int VNC_SECURITY_NONCE_LENGTH = 16;

        // Lookup table for reversing nibble values (used as part of the password encryption)
        private static readonly byte[] ReverseNibble = { 0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE, 0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF };


        internal BinaryReader _reader;

        private Stream _readStream;
        private Stream _writeStream;

        private int _timeoutMiliseconds;

        public RfbProtocol(Stream readStream, Stream writeStream)
        {
            _readStream = readStream;
            _writeStream = writeStream;

            _reader = new BigEndianBinaryReader(readStream);

            _timeoutMiliseconds = DEFAULT_TIMEOUT;
        }

        public void SetTimeout(int miliseconds)
        {
            _timeoutMiliseconds = miliseconds;
        }

        public int ReadFrameBufferUpdate()
        {
            ReadPadding(1);

            return _reader.ReadUInt16();
        }

        public void ReadPadding(int count)
        {
            _reader.ReadBytes(count);
        }

        public async Task<int> ReadSecurityTypeAsync(string password)
        {
            byte[] nonce = new byte[VNC_SECURITY_NONCE_LENGTH];

            await ReadPacketAsync(nonce);

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
            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                cancellationTokenSource.CancelAfter(_timeoutMiliseconds);

                await _writeStream.WriteAsync(response, 0, response.Length, cancellationTokenSource.Token);
                await _writeStream.FlushAsync();
            }

            int securityResult = _reader.ReadInt32();

            return securityResult;
        }

        /// <summary>Reads a packet from the read stream.</summary>
        /// <param name="buffer">The buffer to fill from the network</param>
        /// <returns>An async task.</returns>
        internal async Task ReadPacketAsync(byte[] buffer)
        {
            using (var cancellationTokenSource = new CancellationTokenSource())
            { 
                cancellationTokenSource.CancelAfter(_timeoutMiliseconds);

                await ReadPacketAsync(buffer, 0, buffer.Length, cancellationTokenSource.Token);
            }
        }

        private async Task ReadPacketAsync(byte[] buffer, int offset, int length, CancellationToken cancelToken)
        {
            var remaining = length;

            while (remaining > 0)
            {
                var read = await _readStream.ReadAsync(buffer, offset, remaining, cancelToken);

                if (read <= 0)
                {
                    throw new InvalidDataException();
                }

                remaining -= read;
                offset += read;
            }
        }

        private static void ReverseByteArrayElements(byte[] input)
        {
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = ReverseBits(input[i]);
            }
        }

        private static byte ReverseBits(byte input)
        {
            var high = (input >> 4) & 0x0F;
            var low = input & 0x0F;

            return (byte)((ReverseNibble[low] << 4) | ReverseNibble[high]);
        }
    }
}
