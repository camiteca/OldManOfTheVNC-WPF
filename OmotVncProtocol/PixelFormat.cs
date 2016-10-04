// -----------------------------------------------------------------------------
// <copyright file="PixelFormat.cs" company="Paul C. Roberts">
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
    /// <summary>The pixel format of rectangle updates.</summary>
    public sealed class PixelFormat
    {
        private int _bitsPerPixel;

        /// <summary>
        /// Prevents a default instance of the <see cref="PixelFormat"/> class from being created.
        /// </summary>
        private PixelFormat()
        {
        }

        /// <summary>
        /// Gets or sets the bits per pixel.
        /// </summary>
        public int BitsPerPixel
        {
            get
            {
                return _bitsPerPixel;
            }
            set
            {
                _bitsPerPixel = value;
                BytesPerPixel = _bitsPerPixel / 8;
            }
        }

        /// <summary>
        /// Gets the number of bytes per pixel.
        /// </summary>
        public int BytesPerPixel { get; private set; }

        /// <summary>
        /// Gets Depth.
        /// </summary>
        public int Depth { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the pixel format is BigEndian.
        /// </summary>
        public bool IsBigEndian { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the pixel format is 'TrueColor'.
        /// </summary>
        public bool IsTrueColor { get; private set; }

        /// <summary>
        /// Gets the max value for the Red channel.
        /// </summary>
        public int RedMax { get; private set; }

        /// <summary>
        /// Gets the max value for the Green channel.
        /// </summary>
        public int GreenMax { get; private set; }

        /// <summary>
        /// Gets the max value for the Blue channel.
        /// </summary>
        public int BlueMax { get; private set; }

        /// <summary>
        /// Gets the amount that the red channel is shifted by.
        /// </summary>
        public int RedShift { get; private set; }

        /// <summary>
        /// Gets the amount that the green channel is shifted by.
        /// </summary>
        public int GreenShift { get; private set; }

        /// <summary>
        /// Gets the amount that the blue channel is shifted by.
        /// </summary>
        public int BlueShift { get; private set; }

        /// <summary>
        /// Create a PixelFormat object from a data packet describing it
        /// </summary>
        /// <param name="packet">The data packet.</param>
        /// <returns>A new <see cref="PixelFormat"/> object</returns>
        public static PixelFormat FromServerInit(byte[] packet)
        {
            var format = new PixelFormat();
            
            format.BitsPerPixel = packet[4];
            format.Depth = packet[5];
            
            format.IsBigEndian = packet[6] != 0;
            format.IsTrueColor = packet[7] != 0;
            
            format.RedMax = (packet[8] << 8) | packet[9];
            format.GreenMax = (packet[10] << 8) | packet[11];
            format.BlueMax = (packet[12] << 8) | packet[13];
            
            format.RedShift = packet[14];
            format.GreenShift = packet[15];
            format.BlueShift = packet[16];
            
            return format;
        }

        public override string ToString()
        {
            return $"BitsPerPixel: {BitsPerPixel}\nDepth: {Depth}\nIsBigEndian: {IsBigEndian}\nIsTrueColor: {IsTrueColor}\n" +
                $"RMax: {RedMax}\nGMax: {GreenMax}\nBMax: {BlueMax}\n" +
                $"RShift:{RedShift}\nGShift:{GreenShift}\nBShift:{BlueShift}";
        }
    }
}
