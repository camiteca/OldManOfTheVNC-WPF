// -----------------------------------------------------------------------------
// <copyright file="ExclusiveLock.cs" company="Paul C. Roberts">
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
    using System.Diagnostics;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>Implements an asynchronous exclusive lock.</summary>
    internal sealed class ExclusiveLock
    {
        /// <summary>The currently held lock.</summary>
        private LockEntry currentEntry;

        /// <summary>Enter the exclusive lock.</summary>
        /// <returns>An async task,</returns>
        public async Task<IDisposable> Enter()
        {
#if NETFX_CORE
            LockEntry next = new LockEntry(this);
#else
            LockEntry next = new LockEntry(this, new StackTrace());
#endif

            for (;;)
            {
                LockEntry current = this.currentEntry;
                if (current != null)
                {
                    await current.Wait();
                    await Task.Yield();
                }
                else if (null == Interlocked.CompareExchange(ref this.currentEntry, next, null))
                {
                    return next;
                }
            }
        }

        /// <summary>Represents a lock entry.</summary>
        private class LockEntry : IDisposable
        {
            /// <summary>The task completion source used to signal the exit of the lock.</summary>
            private readonly TaskCompletionSource<bool> source = new TaskCompletionSource<bool>();

            /// <summary>The owning lock.</summary>
            private readonly ExclusiveLock parentLock;

#if NETFX_CORE
            /// <summary>Initializes a new instance of the <see cref="LockEntry"/> class.</summary>
            /// <param name="parent">The owning lock.</param>
            public LockEntry(ExclusiveLock parent)
            {
                this.parentLock = parent;
            }

#else
            /// <summary>The stack trace for this lock.</summary>
            private readonly StackTrace stackTrace;

            /// <summary>Initializes a new instance of the <see cref="LockEntry"/> class.</summary>
            /// <param name="parent">The owning lock.</param>
            /// <param name="trace">The current stack trace.</param>
            public LockEntry(ExclusiveLock parent, StackTrace trace)
            {
                this.parentLock = parent;
                this.stackTrace = trace;
            }
#endif

            /// <summary>Disposes this object.</summary>
            public void Dispose()
            {
                this.source.SetResult(true);
                Interlocked.CompareExchange(ref this.parentLock.currentEntry, null, this);
            }

            /// <summary>Wait for the lock.</summary>
            /// <returns>An async task.</returns>
            public Task Wait()
            {
                return this.source.Task;
            }
        }
    }
}