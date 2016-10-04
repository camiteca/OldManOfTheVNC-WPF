using System.IO;
using System.Text;

namespace PollRobots.OmotVncProtocol
{
    /// <summary>
    /// A BigEndian binary reader implementation. Since this is a custom
    /// implementation only to be used on the VNC protocol, some of the
    /// methods are not overrided. If you need anything that is not
    /// implemented, check the source.
    /// </summary>
    internal class BigEndianBinaryReader
        : BinaryReader
    {
        private byte[] buff = new byte[4];

        public BigEndianBinaryReader(Stream input)
            : base(input)
        {
        }

        public BigEndianBinaryReader(Stream input, Encoding encoding) 
            : base(input, encoding)
        {
        }

        public override ushort ReadUInt16()
        {
            FillBuff(2);
            return (ushort)(((uint)buff[1]) | ((uint)buff[0]) << 8);
        }

        public override short ReadInt16()
        {
            FillBuff(2);
            return (short)(buff[1] & 0xFF | buff[0] << 8);
        }

        public override uint ReadUInt32()
        {
            FillBuff(4);
            return (uint)(((uint)buff[3]) & 0xFF | ((uint)buff[2]) << 8 | ((uint)buff[1]) << 16 | ((uint)buff[0]) << 24);
        }

        public override int ReadInt32()
        {
            FillBuff(4);
            return (int)(buff[3] | buff[2] << 8 | buff[1] << 16 | buff[0] << 24);
        }

        private void FillBuff(int totalBytes)
        {
            int bytesRead = 0;
            int n = 0;

            do
            {
                n = BaseStream.Read(buff, bytesRead, totalBytes - bytesRead);

                if (n == 0)
                    throw new IOException("Unable to read next byte(s).");

                bytesRead += n;
            } while (bytesRead < totalBytes);
        }
    }
}
