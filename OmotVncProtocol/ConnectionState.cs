// -----------------------------------------------------------------------------
// <copyright file="ConnectionState.cs" company="Paul C. Roberts">
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
    /// <summary>
    /// Used to describe the state of a connection.
    /// </summary>
    public enum ConnectionState
    {
        /// <summary>Not connected.</summary>
        Disconnected,
        
        /// <summary>In the process of handshaking.</summary>
        Handshaking,

        /// <summary>In the process of sending a password.</summary>
        SendingPassword,

        /// <summary>Initializing the connection.</summary>
        Initializing,

        /// <summary>The connection is complete.</summary>
        Connected
    }
}