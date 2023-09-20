using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(options => {
        // Utilizamos el certificado del servicio 1
        options.ServerCertificate = X509Certificate2.CreateFromPemFile("service1.crt", "service1.key");
        // Configuramos el protocolo mTLS
        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        // Aceptamos cualquier certificado de cliente porque relaizaremos la autenticación en el middleware de autenticación
        options.AllowAnyClientCertificate();
    });

});

builder
    .Services
    .AddAuthorization(options =>
    {
        // requiere autenticación para acceder a cualquier endpoint
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    })
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // ignoramos la revocación de los certificados
        options.RevocationMode = X509RevocationMode.NoCheck;
        // validamos la fecha de caducidad
        options.ValidateValidityPeriod = true;
        // validamos que el certificado sea de tipo chained
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        // le indicamos que la cadena de confianza la vamos a especificar nosotros
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        // añadimos la CA como raíz de confianza
        var rootcert = new X509Certificate2("ca.crt");
        options.CustomTrustStore.Clear();
        options.CustomTrustStore.Add(rootcert);
    });

var app = builder.Build();
app.UseHttpsRedirection(); // Añadimos el middleware de redirección HTTPS
app.UseAuthentication(); // Añadimos el middleware de autenticación
app.UseAuthorization(); // Añadimos el middleware de autorización
app.MapGet("/", () => "Hello World!");
app.Run();

