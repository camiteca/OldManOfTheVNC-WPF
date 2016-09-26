// -----------------------------------------------------------------------------
// <copyright file="App.xaml.cs" company="Paul C. Roberts">
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

namespace OmotVnc
{
    using System.Windows;
    using System.Windows.Threading;

    /// <summary>The core application class.</summary>
    public partial class App : Application
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="App"/> class.
        /// </summary>
        public App()
        {
        }

        /// <summary>Called on application startup, starts the CCR dispatcher
        /// and creates the main window.</summary>
        /// <param name="e">The startup event arguments.</param>
        protected override void OnStartup(StartupEventArgs e)
        {
            this.DispatcherUnhandledException += this.UnhandledException;
            
            base.OnStartup(e);
            
            var window = new MainWindow();
            this.MainWindow = window;
            
            window.Show();
        }

        /// <summary>Handles the application exit.</summary>
        /// <param name="e">The exit event arguments.</param>
        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
        }

        /// <summary>Process unhandled exceptions</summary>
        /// <remarks>This just ignores exceptions... not healthy.</remarks>
        /// <param name="sender">The parameter is not used.</param>
        /// <param name="e">The unhandled exception arguments</param>
        private void UnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show(e.Exception.ToString());
            e.Handled = true;
        }
    }
}