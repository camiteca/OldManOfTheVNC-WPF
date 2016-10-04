// -----------------------------------------------------------------------------
// <copyright file="ConnectionInfo.cs" company="Microsoft Corporation">
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
    /// <summary>Describes the current connection.</summary>
    public sealed class ConnectionInfo
    {
        /// <summary>
        /// Gets or sets the Name of the connection.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets Width of the screen.
        /// </summary>
        public int Width { get; set; }

        /// <summary>
        /// Gets or sets the Height of the screen.
        /// </summary>
        public int Height { get; set; }

        /// <summary>
        /// Gets the pixel format.
        /// </summary>
        public PixelFormat PixelFormat { get; set; }
    }
}