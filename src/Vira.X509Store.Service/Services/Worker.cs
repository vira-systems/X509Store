/*
 *  Copyright 2025 The Vira.X509Store Project
 *
 *  Licensed under the GNU Affero General Public License, Version 3.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.gnu.org/licenses/agpl-3.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Vira.X509Store project by:
 *  Vira Systems <info@vira.systems>
 */

using System.Management;
using System.Runtime.Versioning;
using Vira.X509Store.Service.Pkcs11;

namespace Vira.X509Store.Service.Services;

/// <summary>
/// Background service that periodically logs its activity and monitors insertion/removal
/// of PKCS#11 (USB/token) devices on Windows. When supported tokens are detected it loads
/// or unloads the PKCS#11 library/provider state accordingly.
/// </summary>
public class Worker : BackgroundService
{
    /// <summary>
    /// PKCS#11 library abstraction used to manage provider load/unload operations.
    /// </summary>
    readonly IPKCS11Library _pKCS11Lib;
    /// <summary>
    /// Logger for diagnostic output.
    /// </summary>
    readonly ILogger<Worker> _logger;
    /// <summary>
    /// Application configuration used to read provider settings ("Providers" section).
    /// </summary>
    readonly IConfiguration _configuration;
    /// <summary>
    /// WMI watcher for device insertion events (Windows only).
    /// </summary>
    readonly ManagementEventWatcher? _insertWatcher;
    /// <summary>
    /// WMI watcher for device removal events (Windows only).
    /// </summary>
    readonly ManagementEventWatcher? _removeWatcher;

    /// <summary>
    /// Initializes a new instance of the <see cref="Worker"/> background service.
    /// </summary>
    /// <param name="pKCS11Lib">PKCS#11 library facade.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="configuration">Configuration root for reading provider list.</param>
    public Worker(IPKCS11Library pKCS11Lib, /*ICacheService cache, IHubContext<TokenHub> hub,*/ ILogger<Worker> logger, IConfiguration configuration)
    {
        //PKCS11Library.Instance.Cache = cache;
        //PKCS11Library.Instance.Hub = hub;
        _pKCS11Lib = pKCS11Lib;
        _logger = logger;
        _configuration = configuration;
        if (OperatingSystem.IsWindows())
        {
            _insertWatcher = new ManagementEventWatcher();
            _removeWatcher = new ManagementEventWatcher();
        }
    }

    /// <summary>
    /// Main execution loop: emits a heartbeat log message every 10 seconds until cancellation.
    /// </summary>
    /// <param name="stoppingToken">Cancellation token signaled when the host is shutting down.</param>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);
            }

            await Task.Delay(10000, stoppingToken);
        }
    }

    /// <summary>
    /// Starts the background service. Loads configured providers and attaches WMI event watchers
    /// for token insertion/removal on Windows platforms.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for startup operations.</param>
    /// <returns>A task representing the asynchronous start operation.</returns>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!cancellationToken.IsCancellationRequested)
        {
            _pKCS11Lib.SupportedProviders = _configuration.GetSection("Providers").Get<List<CspInfo>>() ?? [];

            if (OperatingSystem.IsWindows())
            {
                var insertQuery =
                            "SELECT * FROM __InstanceCreationEvent " +
                            "WITHIN 2 " +
                            "WHERE TargetInstance ISA 'Win32_PnPEntity'";
                var insertWwqlQuery = new WqlEventQuery(insertQuery);

                _insertWatcher!.EventArrived += new EventArrivedEventHandler(Insert_EventArrived);
                _insertWatcher.Query = insertWwqlQuery;
                _insertWatcher.Start();

                var removeQuery =
                            "SELECT * FROM __InstanceDeletionEvent " +
                            "WITHIN 2 " +
                            "WHERE TargetInstance ISA 'Win32_PnPEntity'";
                var removeWwqlQuery = new WqlEventQuery(removeQuery);

                _removeWatcher!.EventArrived += new EventArrivedEventHandler(Remove_EventArrived);
                _removeWatcher.Query = removeWwqlQuery;
                _removeWatcher.Start();
            }
        }

        return base.StartAsync(cancellationToken);
    }

    /// <summary>
    /// Stops the background service and detaches WMI event watchers if running on Windows.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for shutdown operations.</param>
    /// <returns>A task representing the asynchronous stop operation.</returns>
    public override Task StopAsync(CancellationToken cancellationToken)
    {
        if (!cancellationToken.IsCancellationRequested)
        {
            if (OperatingSystem.IsWindows())
            {
                _insertWatcher?.Stop();
                _removeWatcher?.Stop();
            }
        }

        return base.StopAsync(cancellationToken);
    }

    /// <summary>
    /// Disposes resources allocated for WMI watchers on Windows platforms.
    /// </summary>
    public override void Dispose()
    {
        if (OperatingSystem.IsWindows())
        {
            _insertWatcher?.Dispose();
            _removeWatcher?.Dispose();
        }
        base.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Handler invoked when a new PnP entity is detected (device insertion). Attempts to match
    /// the device name to a configured provider and load it if caching/hub contexts are available.
    /// </summary>
    /// <param name="sender">Event sender.</param>
    /// <param name="e">Event args containing WMI data for the inserted device.</param>
    [SupportedOSPlatform("Windows")]
    private void Insert_EventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var mbo = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var name = mbo.Properties["Name"].Value;
            var cspInfo = _pKCS11Lib.SupportedProviders.SingleOrDefault(e => e.Name.Equals(name));

            if (cspInfo != null && _pKCS11Lib.Cache != null && _pKCS11Lib.Hub != null)
            {
                _pKCS11Lib.Load(cspInfo);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{InsertToken}", "Insert Token");
        }
    }

    /// <summary>
    /// Handler invoked when a PnP entity is removed (device removal). Unloads the PKCS#11 library
    /// for known token device names.
    /// </summary>
    /// <param name="sender">Event sender.</param>
    /// <param name="e">Event args containing WMI data for the removed device.</param>
    [SupportedOSPlatform("Windows")]
    private void Remove_EventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var mbo = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var name = mbo.Properties["Name"].Value.ToString();

            switch (name)
            {
                case "USB Token EasyPlay USB Device":
                case "Longmai K3S USB Device":
                case "Rainbow iKey Token":
                    _pKCS11Lib.Unload();
                    break;
                default:
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{RemoveToken}", "Remove Token");
        }
    }
}
