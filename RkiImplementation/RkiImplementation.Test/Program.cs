// See https://aka.ms/new-console-template for more information
using RkiCompleteExample;


using System.Security.Cryptography;

class Program
{
    static async Task Main()
    {
        // 1. Generate Root CA
        var (caCert, caPrivateKey) = CertificateHelper.CreateCaCertificate();

        // 2. Generate Server certificate (issued by CA)
        RSA serverRsa = RSA.Create(2048);
        var serverCert = CertificateHelper.IssueCertificate("KDH-Server", serverRsa, caCert, caPrivateKey);

        // 3. Generate Device certificate (issued by CA)
        RSA deviceRsa = RSA.Create(2048);
        var deviceCert = CertificateHelper.IssueCertificate("POS-Device-001", deviceRsa, caCert, caPrivateKey);

        // 4. Setup components
        var hsm = new HsmSimulator(caCert, serverRsa, serverCert);
        var ped = new PedSimulator(deviceRsa, deviceCert);
        var rkiServer = new RkiServer(hsm);
        var acquireSwitch = new AcquireSwitch(rkiServer);
        var client = new RkiClient(ped, acquireSwitch);

        // 5. Run RKI process
        await client.RunRkiAsync();

        Console.WriteLine("Test finished.");
    }
}