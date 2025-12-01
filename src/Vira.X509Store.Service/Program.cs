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

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Vira.Caching;
using Vira.X509Store.Service;
using Vira.X509Store.Service.Hubs;
using Vira.X509Store.Service.Pkcs11;
using Vira.X509Store.Service.Services;

// Create the WebApplication builder with the command-line args.
// The builder configures hosting, logging, configuration (appsettings.json, env vars, etc.)
var builder = WebApplication.CreateBuilder(args);

if (OperatingSystem.IsWindows())
{
    builder.Host.UseWindowsService();
}

//// Kestrel configuration examples (commented out).
//// You can uncomment and customize if you need explicit HTTP/HTTPS endpoints instead of using appsettings.json.
////var port = Environment.GetEnvironmentVariable("PORT") ?? "5000";
//builder.WebHost.ConfigureKestrel(options =>
//{
//    options.ListenAnyIP(5000/*int.Parse(port)*/); // HTTP
//    // options.ListenAnyIP(5001, listenOptions => listenOptions.UseHttps()); // HTTPS
//    // You can add more endpoints or configure limits, timeouts, etc.
//});

// Configure Kestrel (appsettings.json Kestrel section is honored by default)
// Example override from env variable:
var httpPort = Environment.GetEnvironmentVariable("KESTREL_PORT") ?? "5342";
if (!string.IsNullOrWhiteSpace(httpPort) && int.TryParse(httpPort, out var port))
{
    builder.WebHost.ConfigureKestrel(options => options.ListenLocalhost(port));
}

// NOTE: If you plan to run this application as a Windows Service, enable Windows Service integration:
if (OperatingSystem.IsWindows())
{
    // builder.Host.UseWindowsService(); // <-- Uncomment to enable when publishing/installing as a Windows Service
}

// Add services to the dependency injection container.

// Adds caching extensions provided by the Vira.Caching package (extension method).
// This registers any caching services the application expects.
builder.AddCaching();

// SignalR is used to host real-time hubs (used below with TokenHub).
builder.Services.AddSignalR();

// Register a concrete implementation of ICertificateProvider used by the app.
// This makes ICertificateProvider available via DI for controllers, hubs, hosted services, etc.
builder.Services.AddSingleton<ICertificateProvider, CertificateProvider>();

// Register background worker(s).
// The Worker class is added as a hosted service and will be started automatically with the host.
builder.Services.AddHostedService<Worker>();

// Register PKCS11Library as the IPKCS11Library implementation
builder.Services.AddSingleton<IPKCS11Library, PKCS11Library>();

// Configure CORS policy used by the SignalR client (or other clients).
// Adjust origins, headers and methods as needed for your deployment.
builder.Services.AddCors(options =>
{
    options.AddPolicy("signalr",
        builder => builder
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()
            .SetIsOriginAllowed(origin => true));
});

// Build the application. At this point the DI container and middleware pipeline can be composed.
var app = builder.Build();

// Simple example middleware placeholder — currently it does nothing except call the next middleware.
// Keep this if you intend to add request-level logic (logging, headers, etc.) later.
app.Use(async (context, next) =>
{
    await next.Invoke();
});

// Enable CORS using the default policy configured earlier.
// This must be placed before SignalR hub mapping if requests come from browsers.
app.UseCors("signalr");

// Map a SignalR hub at the "/Store" route. Clients will connect to this path.
app.MapHub<TokenHub>("/Store");

// Start the application. For console runs this blocks the thread; for Windows Service runs the host lifecycle is managed by the service host.
// If you enable Windows Service integration (builder.Host.UseWindowsService()), the process behaves correctly when installed as a service.
app.Run();