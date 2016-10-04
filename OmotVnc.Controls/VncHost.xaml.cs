using PollRobots.OmotVnc.Protocol;
using System;
using System.ComponentModel;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace PollRobots.OmotVnc.Controls
{
    /// <summary>
    /// Interaction logic for VncHost.xaml
    /// </summary>
    public partial class VncHost
        : UserControl, INotifyPropertyChanged
    {
        private const string DEFAULT_CONNECTIONSTATUS_STRING = "Ready to start a connection.";

        private const int DEFAULT_FRAME_WIDTH = 320;
        private const int DEFAULT_FRAME_HEIGHT = 240;

        private const int DEFAULT_SCALE = 1;

        private double _scaleX;
        private double _scaleY;

        private int _frameWidth;
        private int _frameHeight;

        private TcpClient _client;
        private ConnectionOperations _connection;

        private Dispatcher _dispatcher;

        private DispatcherTimer _timer;

        private WriteableBitmap _framebuffer;

        private string _connectionStatusString;
        private Visibility _connectionStatusStringVisibility;

        public VncHost()
        {
            _connectionStatusString = DEFAULT_CONNECTIONSTATUS_STRING;

            _frameWidth = DEFAULT_FRAME_WIDTH;
            _frameHeight = DEFAULT_FRAME_HEIGHT;

            _scaleX = DEFAULT_SCALE;
            _scaleY = DEFAULT_SCALE;

            _dispatcher = Application.Current.Dispatcher;

            InitializeComponent();
        }

        /// <summary>
        /// Gets the frame buffer.
        /// </summary>
        public WriteableBitmap Framebuffer
        {
            get
            {
                return _framebuffer;
            }

            private set
            {
                _framebuffer = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets the connection status string.
        /// </summary>
        public string ConnectionStatusString
        {
            get
            {
                return _connectionStatusString;
            }
            private set
            {
                _connectionStatusString = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets the connection status string visibility.
        /// </summary>
        public Visibility ConnectionStatusStringVisibility
        {
            get
            {
                return _connectionStatusStringVisibility;
            }
            private set
            {
                _connectionStatusStringVisibility = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets the X scale.
        /// </summary>
        public double ScaleX
        {
            get
            {
                return _scaleX;
            }
            private set
            {
                _scaleX = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets the Y scale.
        /// </summary>
        public double ScaleY
        {
            get
            {
                return _scaleY;
            }
            private set
            {
                _scaleY = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets or sets a flag that indicates if the vnc host is connected.
        /// </summary>
        public bool IsConnected
        {
            get { return (bool)GetValue(IsConnectedProperty); }
            set { SetValue(IsConnectedProperty, value); }
        }

        public static readonly DependencyProperty IsConnectedProperty =
            DependencyProperty.Register("IsConnected", typeof(bool), typeof(VncHost));

        /// <summary>
        /// Gets or sets the scale to be applied (in percentage). 
        /// </summary>
        public int Scale
        {
            get { return (int)GetValue(ScaleProperty); }
            set { SetValue(ScaleProperty, value); }
        }

        public static readonly DependencyProperty ScaleProperty =
            DependencyProperty.Register("Scale", typeof(int), typeof(VncHost), new PropertyMetadata(OnScaleChanged));

        private static void OnScaleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var vncHost = d as VncHost;

            vncHost.ScaleX = vncHost.Scale / 100.0;
            vncHost.ScaleY = vncHost.Scale / 100.0;

            vncHost.Scroller.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            vncHost.Scroller.HorizontalScrollBarVisibility = ScrollBarVisibility.Auto;
        }

        /// <summary>
        /// Gets or sets a property that indicates if the bell notifications should be shown.
        /// </summary>
        public bool ShowBellNotifications
        {
            get { return (bool)GetValue(ShowBellNotificationsProperty); }
            set { SetValue(ShowBellNotificationsProperty, value); }
        }

        public static readonly DependencyProperty ShowBellNotificationsProperty =
            DependencyProperty.Register("ShowBellNotifications", typeof(bool), typeof(VncHost), new PropertyMetadata(false));

        /// <summary>
        /// Gets or sets a value that indicates if the scale should fit the window.
        /// </summary>
        public bool ScaleToFit
        {
            get { return (bool)GetValue(ScaleToFitProperty); }
            set { SetValue(ScaleToFitProperty, value); }
        }

        public static readonly DependencyProperty ScaleToFitProperty =
            DependencyProperty.Register("ScaleToFit", typeof(bool), typeof(VncHost), new PropertyMetadata(OnScaleFitChanged));

        private static void OnScaleFitChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
        {
            var vncHost = sender as VncHost;

            if (vncHost.FrameHeight == 0 || vncHost.FrameWidth == 0)
            {
                vncHost.ScaleX = 1;
                vncHost.ScaleY = 1;

                vncHost.Scroller.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
                vncHost.Scroller.HorizontalScrollBarVisibility = ScrollBarVisibility.Auto;
            }
            else
            {
                vncHost.ScaleX = vncHost.DisplayArea.ActualWidth / vncHost.FrameWidth;
                vncHost.ScaleY = vncHost.DisplayArea.ActualHeight / vncHost.FrameHeight;

                vncHost.Scroller.VerticalScrollBarVisibility = ScrollBarVisibility.Hidden;
                vncHost.Scroller.HorizontalScrollBarVisibility = ScrollBarVisibility.Hidden;
            }
        }

        /// <summary>
        /// Gets or sets a property that indicates if the local cursor should be enabled.
        /// </summary>
        public bool UseLocalCursor
        {
            get { return (bool)GetValue(UseLocalCursorProperty); }
            set { SetValue(UseLocalCursorProperty, value); }
        }

        public static readonly DependencyProperty UseLocalCursorProperty =
            DependencyProperty.Register("UseLocalCursor", typeof(bool), typeof(VncHost), new PropertyMetadata(OnUseLocalCursorChanged));

        private static void OnUseLocalCursorChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
        {
            var vncHost = sender as VncHost;

            if (vncHost != null)
            {
                bool useLocalCursor = (bool)args.NewValue;

                if (useLocalCursor)
                {
                    vncHost.DisplaySurface.Cursor = Cursors.Arrow;
                }
                else
                {
                    vncHost.DisplaySurface.Cursor = Cursors.None;
                }
            }
        }

        /// <summary>
        /// Gets or sets the frame width.
        /// </summary>
        public int FrameWidth
        {
            get
            {
                return _frameWidth;
            }
            private set
            {
                _frameWidth = value;
                RaisePropertyChanged();
            }
        }

        /// <summary>
        /// Gets or sets the frame height.
        /// </summary>
        public int FrameHeight
        {
            get
            {
                return _frameHeight;
            }
            private set
            {
                _frameHeight = value;
                RaisePropertyChanged();
            }
        }

        public async Task ConnectAsync(string server, int port, string password)
        {
            bool isConnected = false;

            ConnectionStatusStringVisibility = Visibility.Visible;

            SetStatusText("Connecting to " + server);

            try
            {
                _client = new TcpClient();
                _client.SendTimeout = TimeSpan.FromSeconds(30).Milliseconds;

                await _client.ConnectAsync(server, port);

                var stream = _client.GetStream();

                _connection = Connection.CreateFromStream(stream, HandleRectangle, HandleConnectionState, HandleException);

                isConnected = await DoConnect(password);
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                {
                    SetStatusText("Error connecting: " + e.InnerException.Message);
                }
                else
                {
                    SetStatusText("Error connecting: " + e.Message);
                }

                isConnected = false;
            }

            IsConnected = isConnected;
        }

        /// <summary>Disconnect from the server if possible</summary>
        public async Task DisconnectAsync()
        {
            if (_connection != null)
            {
                await _connection.ShutdownAsync();

                _connection = null;
            }

            if (_client != null &&
                _client.Connected)
            {
                _client.Client.Disconnect(true);
                _client.Close();
            }

            IsConnected = false;

            //TODO: we should clean up the image and set the label visibility.
        }

        /// <summary>Handles ticks on the frame update timer.</summary>
        /// <param name="sender">The paramter is not used.</param>
        /// <param name="e">The parameter is not used.</param>
        private void OnTimer(object sender, EventArgs e)
        {
            if (_connection == null)
            {
                _timer.Stop();
            }
            else
            {
                _connection.UpdateAsync(false);
            }
        }

        /// <summary>Run the VNC protocol connection process</summary>
        /// <param name="password">The password.</param>
        /// <returns>Standard CCR task enumerator</returns>
        private async Task<bool> DoConnect(string password)
        {
            bool requiresPassword;

            SetStatusText("Handshaking...");

            try
            {
                requiresPassword = await _connection.HandshakeAsync();
            }
            catch (Exception exception)
            {
                SetStatusText("Error handshaking: ", exception);

                return false;
            }

            if (requiresPassword)
            {
                SetStatusText("Sending password...");

                try
                {
                    await _connection.SendPasswordAsync(password);
                }
                catch (Exception exception)
                {
                    SetStatusText("Error sending password: ", exception);

                    return false;
                }
            }

            SetStatusText("Initializing...");

            try
            {
                await _connection.InitializeAsync(true);

                _connection.BellEvent += (s, e) => DoInvoke(HandleBell);
            }
            catch (Exception exception)
            {
                SetStatusText("Error initializing: ", exception);

                return false;
            }

            try
            {
                ConnectionInfo connectionInfo = _connection.GetConnectionInfo();

                StartFramebuffer(connectionInfo);
            }
            catch (Exception exception)
            {
                SetStatusText("Error getting connection info: ", exception);

                return false;
            }

            return true;
        }

        /// <summary>Initialize the frame buffer with the reported width and 
        /// height from the server.</summary>
        /// <param name="info">The connection info.</param>
        private void StartFramebuffer(ConnectionInfo info)
        {
            DoInvoke(() =>
            {
                ConnectionStatusStringVisibility = Visibility.Collapsed;

                FrameWidth = Math.Max(info.Width, 320);
                FrameHeight = Math.Max(info.Height, 240);

                var pixelFormat = PixelFormats.Bgr32;

                if (info.PixelFormat.BitsPerPixel == 16)
                {
                    pixelFormat = PixelFormats.Bgr565;
                }

                Framebuffer = new WriteableBitmap(
                    FrameWidth,
                    FrameHeight,
                    96,
                    96,
                    pixelFormat,
                    null);

                _connection.StartAsync();
                _connection.UpdateAsync(true);

                _timer = new DispatcherTimer(
                    TimeSpan.FromMilliseconds(10),
                    DispatcherPriority.Background,
                    OnTimer,
                    Dispatcher);

                _timer.Start();
            });
        }

        public async Task UpdateAsync()
        {
            if (_connection != null)
            {
                await _connection.UpdateAsync(true);
            }
        }

        /// <summary>Handles an update to a rectangle in the frame buffer</summary>
        /// <remarks>This assumes that the rectangle is completely within the
        /// frame buffer dimensions and that the pixel format is BGR32</remarks>
        /// <param name="update">The update information</param>
        private void HandleRectangle(Rectangle update)
        {
            DoInvoke(() =>
            {
                var rectangle = new Int32Rect(
                    update.Left,
                    update.Top,
                    update.Width,
                    update.Height);

                int stride = (update.Width * Framebuffer.Format.BitsPerPixel + 7) / 8;

                Framebuffer.WritePixels(rectangle, update.Pixels, stride, 0);
            });
        }

        private void HandleBell()
        {
            if (ShowBellNotifications)
            {
                var storyboard = new Storyboard();
                var animation = new DoubleAnimation(0.8, 0.0, new Duration(TimeSpan.FromSeconds(0.5)));
                animation.EasingFunction = new BackEase { EasingMode = EasingMode.EaseInOut };
                Storyboard.SetTarget(animation, Bell);
                Storyboard.SetTargetProperty(animation, new PropertyPath(OpacityProperty));
                storyboard.Children.Add(animation);
                storyboard.Begin();
            }
        }

        /// <summary>Handles a change in the connection state as reported by 
        /// the protocol service.</summary>
        /// <param name="state">The new state.</param>
        private void HandleConnectionState(ConnectionState state)
        {
            if (state == ConnectionState.Disconnected)
            {
                DoInvoke(async () =>
                {
                    SetStatusText("Disconnected (no reason given).");

                    await DisconnectAsync();

                    if (_timer != null)
                    {
                        _timer.Stop();
                        _timer = null;
                    }
                });
            }
        }

        /// <summary>Displays any error message from the protocol</summary>
        /// <param name="exception">The exception raised by the protocol 
        /// service.</param>
        private void HandleException(Exception exception)
        {
            SetStatusText("Error from protocol: ", exception);
        }

        private void SetStatusText(string newstatus)
        {
            ConnectionStatusString = newstatus;
        }

        private void SetStatusText(string message, Exception exception)
        {
            if (exception.InnerException != null)
            {
                SetStatusText(message, exception.InnerException);
            }
            else
            {
                SetStatusText(message + exception.Message);
            }

            DoInvoke(async () => await DisconnectAsync());
        }

        /// <summary>Handles the display size changing.</summary>
        /// <param name="sender">The parameter is not used.</param>
        /// <param name="e">The parameter is not used.</param>
        private void DisplayAreaSizeChanged(object sender, SizeChangedEventArgs e)
        {
            if (ScaleToFit)
            {
                ScaleX = DisplayArea.ActualWidth / FrameWidth;
                ScaleY = DisplayArea.ActualHeight / FrameHeight;
            }
        }

        /// <summary>Handles mouse move events in the display area.</summary>
        /// <remarks>This sends pointer events to the server if there is a 
        /// connection, and the display service is focussed</remarks>
        /// <param name="sender">The parameter is not used.</param>
        /// <param name="e">The mouse move event arguments</param>
        private async void HandleMouseMove(object sender, MouseEventArgs e)
        {
            if (_connection != null)
            {
                Point point = e.GetPosition(DisplaySurface);

                AutoScroll(point.X, point.Y);

                if (DisplaySurface.IsFocused == false && e.LeftButton == MouseButtonState.Pressed)
                {
                    DisplaySurface.Focus();

                    return;
                }

                // On a conventional mouse, buttons 1, 2, and 3 correspond to the left,
                // middle, and right buttons on the mouse.
                int buttons = (e.LeftButton == MouseButtonState.Pressed ? 1 : 0) |
                    (e.MiddleButton == MouseButtonState.Pressed ? 2 : 0) |
                    (e.RightButton == MouseButtonState.Pressed ? 4 : 0);

                await _connection.SetPointerAsync(buttons, (int)point.X, (int)point.Y);
            }
        }

        private void HandleMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (_connection != null)
            {
                Point point = e.GetPosition(DisplaySurface);

                // On a wheel mouse, each step of the wheel upwards is represented by a
                // press and release of button 4, and each step downwards is represented 
                // by a press and release of button 5.

                byte mask = 0;

                if (e.Delta > 0)
                {
                    mask += 8;
                }
                else if (e.Delta < 0)
                {
                    mask += 16;
                }

                if (mask != 0)
                {
                    _connection.SetPointerAsync(mask, (int)point.X, (int)point.Y);
                }
            }
        }

        /// <summary>Handles text input events, sending a sequence of down, up
        /// messages to the server, followed by a single update.</summary>
        /// <param name="sender">The parameter is not used.</param>
        /// <param name="e">The text input event.</param>
        private async void HandleTextInput(object sender, TextCompositionEventArgs e)
        {
            if (_connection == null)
            {
                return;
            }

            foreach (var character in e.Text)
            {
                await _connection.SendKeyAsync(true, character, false);
                await _connection.SendKeyAsync(false, character, false);
            }

            await _connection.UpdateAsync(false);
        }

        /// <summary>Handles key up and down events<summary>
        /// <remarks>This translates the key-code from windows to VNC and
        /// sends the key operation to the server. The Left and Right windows
        /// keys are mapped to left and right meta respectively.</remarks>
        /// <param name="sender">The parameter is not used.</param>
        /// <param name="e">The key event arguments.</param>
        private async void HandleKey(object sender, KeyEventArgs e)
        {
            if (_connection == null || e.IsRepeat)
            {
                return;
            }

            uint key = 0;
            switch (e.Key)
            {
                case Key.Back:
                    key = (uint)VncKey.BackSpace;
                    break;
                case Key.Tab:
                    key = (uint)VncKey.Tab;
                    break;
                case Key.Return:
                    key = (uint)VncKey.Return;
                    break;
                case Key.Escape:
                    key = (uint)VncKey.Escape;
                    break;
                case Key.Insert:
                    key = (uint)VncKey.Insert;
                    break;
                case Key.Delete:
                    key = (uint)VncKey.Delete;
                    break;
                case Key.Home:
                    key = (uint)VncKey.Home;
                    break;
                case Key.End:
                    key = (uint)VncKey.End;
                    break;
                case Key.PageUp:
                    key = (uint)VncKey.PageUp;
                    break;
                case Key.PageDown:
                    key = (uint)VncKey.PageDown;
                    break;
                case Key.Left:
                    key = (uint)VncKey.Left;
                    break;
                case Key.Up:
                    key = (uint)VncKey.Up;
                    break;
                case Key.Right:
                    key = (uint)VncKey.Right;
                    break;
                case Key.Down:
                    key = (uint)VncKey.Down;
                    break;
                case Key.F1:
                    key = (uint)VncKey.F1;
                    break;
                case Key.F2:
                    key = (uint)VncKey.F2;
                    break;
                case Key.F3:
                    key = (uint)VncKey.F3;
                    break;
                case Key.F4:
                    key = (uint)VncKey.F4;
                    break;
                case Key.F5:
                    key = (uint)VncKey.F5;
                    break;
                case Key.F6:
                    key = (uint)VncKey.F6;
                    break;
                case Key.F7:
                    key = (uint)VncKey.F7;
                    break;
                case Key.F8:
                    key = (uint)VncKey.F8;
                    break;
                case Key.F9:
                    key = (uint)VncKey.F9;
                    break;
                case Key.F10:
                    key = (uint)VncKey.F10;
                    break;
                case Key.F11:
                    key = (uint)VncKey.F11;
                    break;
                case Key.F12:
                    key = (uint)VncKey.F12;
                    break;
                case Key.LeftShift:
                    key = (uint)VncKey.ShiftLeft;
                    break;
                case Key.RightShift:
                    key = (uint)VncKey.ShiftRight;
                    break;
                case Key.LeftCtrl:
                    key = (uint)VncKey.ControlLeft;
                    break;
                case Key.RightCtrl:
                    key = (uint)VncKey.ControlRight;
                    break;
                case Key.LWin:
                    key = (uint)VncKey.MetaLeft;
                    break;
                case Key.RWin:
                    key = (uint)VncKey.MetaRight;
                    break;
                case Key.LeftAlt:
                    key = (uint)VncKey.AltLeft;
                    break;
                case Key.RightAlt:
                    key = (uint)VncKey.AltRight;
                    break;
                default:
                    var modifiers = Keyboard.Modifiers;
                    if (!modifiers.HasFlag(ModifierKeys.Control) &&
                        !modifiers.HasFlag(ModifierKeys.Alt))
                    {
                        return;
                    }

                    key = (uint)TranslateKey(modifiers.HasFlag(ModifierKeys.Shift), e.Key);
                    break;
            }

            e.Handled = true;

            await _connection.SendKeyAsync(e.IsDown, key, update: true);
        }

        private char TranslateKey(bool isShifted, Key key)
        {
            switch (key)
            {
                case Key.D0: return isShifted ? ')' : '0';
                case Key.D1: return isShifted ? '!' : '1';
                case Key.D2: return isShifted ? '@' : '2';
                case Key.D3: return isShifted ? '#' : '3';
                case Key.D4: return isShifted ? '$' : '4';
                case Key.D5: return isShifted ? '%' : '5';
                case Key.D6: return isShifted ? '^' : '6';
                case Key.D7: return isShifted ? '&' : '7';
                case Key.D8: return isShifted ? '*' : '8';
                case Key.D9: return isShifted ? '(' : '9';

                case Key.NumPad0: return '0';
                case Key.NumPad1: return '1';
                case Key.NumPad2: return '2';
                case Key.NumPad3: return '3';
                case Key.NumPad4: return '4';
                case Key.NumPad5: return '5';
                case Key.NumPad6: return '6';
                case Key.NumPad7: return '7';
                case Key.NumPad8: return '8';
                case Key.NumPad9: return '9';

                case Key.Decimal: return isShifted ? '>' : '.';
                case Key.Divide: return isShifted ? '?' : '/';
                case Key.Space: return ' ';
                case Key.Subtract: return isShifted ? '_' : '-';

                case Key.OemBackslash: return isShifted ? '|' : '\\';
                case Key.OemCloseBrackets: return isShifted ? '}' : ']';
                case Key.OemComma: return isShifted ? '<' : ',';
                case Key.OemMinus: return isShifted ? '_' : '-';
                case Key.OemOpenBrackets: return isShifted ? '{' : '[';
                case Key.OemPeriod: return isShifted ? '>' : '.';
                case Key.OemPipe: return isShifted ? '|' : '\\';
                case Key.OemPlus: return isShifted ? '+' : '=';
                case Key.OemQuestion: return isShifted ? '?' : '/';
                case Key.OemQuotes: return isShifted ? '"' : '\'';
                case Key.OemSemicolon: return isShifted ? ':' : ';';
                case Key.OemTilde: return isShifted ? '~' : '`';

                case Key.A: return isShifted ? 'A' : 'a';
                case Key.B: return isShifted ? 'B' : 'b';
                case Key.C: return isShifted ? 'C' : 'c';
                case Key.D: return isShifted ? 'D' : 'd';
                case Key.E: return isShifted ? 'E' : 'e';
                case Key.F: return isShifted ? 'F' : 'f';
                case Key.G: return isShifted ? 'G' : 'g';
                case Key.H: return isShifted ? 'H' : 'h';
                case Key.I: return isShifted ? 'I' : 'i';
                case Key.J: return isShifted ? 'J' : 'j';
                case Key.K: return isShifted ? 'K' : 'k';
                case Key.L: return isShifted ? 'L' : 'l';
                case Key.M: return isShifted ? 'M' : 'm';
                case Key.N: return isShifted ? 'N' : 'n';
                case Key.O: return isShifted ? 'O' : 'o';
                case Key.P: return isShifted ? 'P' : 'p';
                case Key.Q: return isShifted ? 'Q' : 'q';
                case Key.R: return isShifted ? 'R' : 'r';
                case Key.S: return isShifted ? 'S' : 's';
                case Key.T: return isShifted ? 'T' : 't';
                case Key.U: return isShifted ? 'U' : 'u';
                case Key.V: return isShifted ? 'V' : 'v';
                case Key.W: return isShifted ? 'W' : 'w';
                case Key.X: return isShifted ? 'X' : 'x';
                case Key.Y: return isShifted ? 'Y' : 'y';
                case Key.Z: return isShifted ? 'Z' : 'z';
                default:
                    return '?';
            }
        }

        /// <summary>
        /// If the mouse is near the edge of the visible region and scroll bars
        /// are visible, then automatically scroll to the obvious direction
        /// </summary>
        /// <param name="x">The x-coordinate of the mouse</param>
        /// <param name="y">The y-coordinate of the moust</param>
        private void AutoScroll(double x, double y)
        {
            if (Scroller.ComputedHorizontalScrollBarVisibility == Visibility.Visible)
            {
                if (x < Scroller.HorizontalOffset + 10)
                {
                    Scroller.ScrollToHorizontalOffset(
                        Math.Max(0, Scroller.HorizontalOffset - 1));
                }
                else if (x > Scroller.HorizontalOffset + (Scroller.ExtentWidth - Scroller.ScrollableWidth) - 10)
                {
                    Scroller.ScrollToHorizontalOffset(Math.Min(
                        Scroller.HorizontalOffset + 1,
                        Scroller.ScrollableWidth));
                }
            }

            if (Scroller.ComputedVerticalScrollBarVisibility == Visibility.Visible)
            {
                if (y < Scroller.VerticalOffset + 10)
                {
                    Scroller.ScrollToVerticalOffset(
                        Math.Max(0, Scroller.VerticalOffset - 1));
                }
                else if (y > Scroller.VerticalOffset + (Scroller.ExtentHeight - Scroller.ScrollableHeight) - 10)
                {
                    Scroller.ScrollToVerticalOffset(Math.Min(
                        Scroller.VerticalOffset + 1,
                        Scroller.ScrollableHeight));
                }
            }
        }

        public void DoInvoke(Action action)
        {
            _dispatcher.BeginInvoke(action);
        }

        public event PropertyChangedEventHandler PropertyChanged;

        public void RaisePropertyChanged([CallerMemberName]string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
