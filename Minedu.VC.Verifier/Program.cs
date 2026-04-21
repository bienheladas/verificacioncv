using Microsoft.Extensions.Configuration;
using Minedu.VC.Verifier.Models;
using Minedu.VC.Verifier.Services;
using Serilog;
using Serilog.Formatting.Json;

var builder = WebApplication.CreateBuilder(args);

// ===========================================
// 🔧 SERILOG CONFIG ROBUSTA (con fallback)
// ===========================================
// Cargar configuraciones desde appsettings.json
var logConfig = builder.Configuration.GetSection("Logging");

// Obtener ruta de logs desde la configuración
var logPath = logConfig.GetValue<string>("LogPath");

// Intentar crear el directorio de logs
try
{
    // Crear el directorio si no existe
    Directory.CreateDirectory(logPath);

    // Test de escritura
    var testFile = Path.Combine(logPath, "write-test.txt");
    File.WriteAllText(testFile, $"Write OK at {DateTime.Now}");

    Log.Information("✔ Escritura exitosa en la ruta de logs: {LogPath}", logPath);
}
catch (Exception ex)
{
    Log.Fatal(ex, "❌ No se pudo escribir en la ruta de logs configurada: {LogPath}", logPath);
    throw new InvalidOperationException("No se puede escribir en la ruta de logs. Verifica los permisos.", ex);
}

Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .Filter.ByExcluding(e => e.RenderMessage().Contains("/verifier/result/"))
    .WriteTo.Console()
    .WriteTo.File(
        path: Path.Combine(logPath, "verifier-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 7,
        shared: true)
    .CreateLogger();

Log.Information("✔ Serilog inicializado OK. Carpeta Log final = {Dir}", logPath);
Log.Information("✔ AppBaseDirectory = {BaseDir}", AppContext.BaseDirectory);

// ==================================================
// Configuración de servicios
// ==================================================

builder.Host.UseSerilog();

// Add services to the container.
builder.Services.Configure<VerifierConfig>(
builder.Configuration.GetSection("Verifier"));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<string>(logPath);
builder.Services.AddSingleton<SessionService>();
builder.Services.AddSingleton<VerificationService>();
builder.Services.AddSingleton<TrustedIssuerService>();
builder.Services.AddHttpClient<DidWebResolver>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy => policy.AllowAnyOrigin()
                        .AllowAnyHeader()
                        .AllowAnyMethod());
});

var app = builder.Build();

Log.Information("Verifier API iniciado. Entorno: {Env}", app.Environment.EnvironmentName);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.UseCors("AllowAll");
app.MapControllers();


try
{
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "El host del Verifier falló durante el inicio");
}
finally
{
    Log.CloseAndFlush();
}
