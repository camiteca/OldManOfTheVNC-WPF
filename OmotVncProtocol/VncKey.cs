// -----------------------------------------------------------------------------
// <copyright file="VncKey.cs" company="Paul C. Roberts">
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

    /// <summary>The key codes used by the VNC protocol</summary>
    public enum VncKey
    {
        /// <summary>Represents an unknown key</summary>
        Unknown = 0,

        /// <summary>The backspace key</summary>
        BackSpace = 0xFF08,

        /// <summary>The tab key</summary>
        Tab = 0xFF09,

        /// <summary>The return key</summary>
        Return = 0xFF0D,

        /// <summary>The enter key</summary>
        Enter = 0xFF0D,

        /// <summary>The escape key</summary>
        Escape = 0xFF1B,

        /// <summary>The insert key</summary>
        Insert = 0xFF63,

        /// <summary>The delete key</summary>
        Delete = 0xFFFF,

        /// <summary>The home key</summary>
        Home = 0xFF50,

        /// <summary>The end key</summary>
        End = 0xFF57,

        /// <summary>The Page Up key</summary>
        PageUp = 0xFF55,

        /// <summary>The Page Down key</summary>
        PageDown = 0xFF56,

        /// <summary>The Left key</summary>
        Left = 0xFF51,

        /// <summary>The Up key</summary>
        Up = 0xFF52,

        /// <summary>The Right key</summary>
        Right = 0xFF53,

        /// <summary>The down key</summary>
        Down = 0xFF54,

        /// <summary>The F1 key</summary>
        F1 = 0xFFBE,

        /// <summary>The F2 key</summary>
        F2 = 0xFFBF,

        /// <summary>The F3 key</summary>
        F3 = 0xFFC0,

        /// <summary>The F4 key</summary>
        F4 = 0xFFC1,

        /// <summary>The F5 key</summary>
        F5 = 0xFFC2,

        /// <summary>The F6 key</summary>
        F6 = 0xFFC3,

        /// <summary>The F7 key</summary>
        F7 = 0xFFC4,

        /// <summary>The F8 key</summary>
        F8 = 0xFFC5,

        /// <summary>The F9 key</summary>
        F9 = 0xFFC6,

        /// <summary>The F10 key</summary>
        F10 = 0xFFC7,

        /// <summary>The F11 key</summary>
        F11 = 0xFFC8,

        /// <summary>The F12 key</summary>
        F12 = 0xFFC9,

        /// <summary>The Left shift key</summary>
        ShiftLeft = 0xFFE1,

        /// <summary>The Right shift key</summary>
        ShiftRight = 0xFFE2,

        /// <summary>The left control key</summary>
        ControlLeft = 0xFFE3,

        /// <summary>The right control key</summary>
        ControlRight = 0xFFE4,

        /// <summary>The Caps Lock key</summary>
        CapsLock = 0xFFE5,

        /// <summary>The left meta key</summary>
        MetaLeft = 0xFFE7,

        /// <summary>The right meta key</summary>
        MetaRight = 0xFFE8,

        /// <summary>The left alt key</summary>
        AltLeft = 0xFFE9,

        /// <summary>The right alt key</summary>
        AltRight = 0xFFEA
    }
}
