// -----------------------------------------------------------------------------
// <copyright file="Rectangle.cs" company="Paul C. Roberts">
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

using PollRobots.OmotVncProtocol;
using System;
using System.Threading.Tasks;

namespace PollRobots.OmotVnc.Protocol
{
    /// <summary>Message type used to communicate a rectangle of pixels to the 
    /// client.</summary>
    public sealed class Rectangle
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Rectangle"/> class.
        /// </summary>
        /// <param name="left">The left edge of the rectangle.</param>
        /// <param name="top">The top edge of the rectangle.</param>
        /// <param name="width">The width of the rectangle.</param>
        /// <param name="height">The height of the rectangle.</param>
        public Rectangle(int left, int top, int width, int height, PixelFormat pixelFormat)
        {
            Left = left;
            Top = top;
            Width = width;
            Height = height;
            PixelFormat = pixelFormat;
            Pixels = new byte[width * height * pixelFormat.BytesPerPixel];
        }

        /// <summary>
        /// Gets the Left edge of the rectangle.
        /// </summary>
        public int Left { get; private set; }
        
        /// <summary>
        /// Gets the Top edge of the rectangle.
        /// </summary>
        public int Top { get; private set; }
        
        /// <summary>
        /// Gets the width of the rectangle.
        /// </summary>
        public int Width { get; private set; }
        
        /// <summary>
        /// Gets the height of the rectangle.
        /// </summary>
        public int Height { get; private set; }

        public PixelFormat PixelFormat { get; private set; }

        /// <summary>
        /// Gets the pixel values of the rectangle.
        /// </summary>
        public byte[] Pixels { get; set; }

        internal async Task DecodeAsync(RfbProtocol protocol, int encoding)
        {
            if(encoding != 0) // raw encoding
            {
                throw new NotImplementedException();
            }

            await protocol.ReadPacketAsync(Pixels);

            if (PixelFormat.IsBigEndian)
            {
                byte[] transformedPixels = new byte[Pixels.Length];

                for (int i = 0; i < Pixels.Length; i += PixelFormat.BytesPerPixel)
                {
                    for (int j = 0; j < PixelFormat.BytesPerPixel / 2; j++)
                    {
                        byte tempByte1 = Pixels[i + j];
                        byte tempByte2 = Pixels[i - 1 + (PixelFormat.BytesPerPixel - j)];

                        transformedPixels[i + j] = tempByte2;

                        transformedPixels[i - 1 + (PixelFormat.BytesPerPixel - j)] = tempByte1;

                    }
                }

                Pixels = transformedPixels;
            }
        }
    }
}