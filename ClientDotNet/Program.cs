using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Collections.Generic;
using System.Threading.Tasks;

record ClientConf(string Name, int Port, string ServerName, bool ExpectedOK);

class Program
{
    static HttpClient CreateStandardClient(X509Certificate2 caCert, string serverName)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (httpRequest, cert, chain, errors) =>
            {
                if (cert is not X509Certificate2 cert2)
                    return false;

                // Custom chain with custom root CA.
                var customChain = new X509Chain();
                customChain.ChainPolicy.ExtraStore.Add(caCert);
                customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                bool isValid = customChain.Build(cert2);

                // Simulate SNI override by matching hostname.
                bool nameMatches = cert2.GetNameInfo(X509NameType.DnsName, false).Equals(serverName, StringComparison.OrdinalIgnoreCase);

                return isValid && nameMatches;
            }
        };

        return new HttpClient(handler);
    }

    static async Task TestRequest(ClientConf conf, HttpClient client)
    {
        var url = $"https://localhost:{conf.Port}/";
        try
        {
            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            if (conf.ExpectedOK)
            {
                Console.WriteLine($"  \x1b[32m✔\x1b[0m Request to :{conf.Port} (as {conf.ServerName}) succeeded");
                Console.WriteLine($"    - Response: {body}");
            }
            else
            {
                Console.WriteLine($"  \x1b[31m✘\x1b[0m Request to :{conf.Port} (as {conf.ServerName}) succeeded but was not expected to");
            }
        }
        catch (Exception ex)
        {
            if (conf.ExpectedOK)
            {
                Console.WriteLine($"  \x1b[31m✘\x1b[0m Request to :{conf.Port} (as {conf.ServerName}) failed: {ex.Message}");
            }
            else
            {
                Console.WriteLine($"  \x1b[32m✔\x1b[0m Request to :{conf.Port} (as {conf.ServerName}) failed as expected: {ex.Message}");
            }
        }
    }

    static async Task Main()
    {
        var caPem = await File.ReadAllTextAsync("ca/root/root.cert.pem");

        // Parse PEM manually
        string base64 = caPem
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\r", "")
            .Replace("\n", "");

        byte[] certBytes = Convert.FromBase64String(base64);
        
        var caCert = X509CertificateLoader.LoadCertificate(certBytes);

        var configs = new List<ClientConf>
        {
            new("domain_correct_ou_correct", 8443, "only-this-domain-is-allowed.com", true),
            new("domain_incorrect_ou_correct", 8444, "only-this-domain-is-allowed.com", false),
            new("domain_correct_ou_incorrect", 8445, "this-domain-is-not-allowed.com", false),
            new("domain_incorrect_ou_incorrect", 8446, "this-domain-is-not-allowed.com", false),
        };

        Console.WriteLine("\nTesting using the standard TLS client");
        Console.WriteLine("=====================================\n");

        foreach (var conf in configs)
        {
            Console.WriteLine($"Testing {conf.Name}");
            using var client = CreateStandardClient(caCert, conf.ServerName);
            await TestRequest(conf, client);
            Console.WriteLine();
        }
    }
}

