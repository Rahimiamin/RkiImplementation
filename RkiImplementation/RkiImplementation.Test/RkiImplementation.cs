using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RkiCompleteExample
{
    // ========== Message Models ==========
    public class RkiRequest
    {
        public Guid SessionId { get; set; }
        public int Step { get; set; }
        public string? DeviceCertB64 { get; set; }
        public string? SignedChallengeB64 { get; set; }
        public string? ClientNonceB64 { get; set; }
    }

    public class RkiResponse
    {
        public Guid SessionId { get; set; }
        public int Step { get; set; }
        public bool Success { get; set; }
        public string? Error { get; set; }
        public string? ChallengeB64 { get; set; }
        public string? ServerCertB64 { get; set; }
        public string? SignedChallengeB64 { get; set; }
        public string? EncryptedSessionKeyB64 { get; set; }
        public string? EncryptedTmkB64 { get; set; }
        public string? EncryptedOperationalKeysB64 { get; set; }
    }

    // ========== Certificate Helper with proper BasicConstraints ==========
    public static class CertificateHelper
    {
        public static (X509Certificate2 caCert, RSA caPrivateKey) CreateCaCertificate()
        {
            using RSA rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=PaymentRootCA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            var caCert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(10));
            return (caCert, rsa);
        }

        public static X509Certificate2 IssueCertificate(string cn, RSA subjectPublicKey, X509Certificate2 caCert, RSA caPrivateKey)
        {
            var req = new CertificateRequest($"CN={cn}", subjectPublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            byte[] serial = new byte[16];
            RandomNumberGenerator.Fill(serial);
            using var cert = req.Create(caCert, DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1), serial);
            return cert.CopyWithPrivateKey(subjectPublicKey);
        }
    }

    // ========== PED Simulator (Client Side) ==========
    public class PedSimulator
    {
        private readonly RSA _devicePrivateKey;
        private readonly X509Certificate2 _deviceCert;
        private byte[]? _sessionKey;
        private byte[]? _tmk;

        public PedSimulator(RSA devicePrivateKey, X509Certificate2 deviceCert)
        {
            _devicePrivateKey = devicePrivateKey;
            _deviceCert = deviceCert;
        }

        public string GetDeviceCertBase64() => Convert.ToBase64String(_deviceCert.Export(X509ContentType.Cert));

        public byte[] SignData(byte[] data) =>
            _devicePrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        public bool VerifySignature(byte[] data, byte[] signature, RSA publicKey) =>
            publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        public byte[] DecryptRsa(byte[] encryptedData) =>
            _devicePrivateKey.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);

        public void StoreSessionKey(byte[] decryptedSessionKey)
        {
            _sessionKey = decryptedSessionKey;
            Console.WriteLine("   [PED] Session Key stored.");
        }

        public byte[] DecryptAesGcm(byte[] cipherTextWithIvAndTag)
        {
            if (_sessionKey == null) throw new InvalidOperationException("Session Key not available");
            byte[] iv = cipherTextWithIvAndTag[..12];
            byte[] cipherText = cipherTextWithIvAndTag[12..^16];
            byte[] tag = cipherTextWithIvAndTag[^16..];
            using var aes = new AesGcm(_sessionKey, 16);
            byte[] plain = new byte[cipherText.Length];
            aes.Decrypt(iv, cipherText, tag, plain);
            return plain;
        }

        public void StoreTmk(byte[] decryptedTmk)
        {
            _tmk = decryptedTmk;
            Console.WriteLine("   [PED] TMK stored.");
        }

        public byte[] DecryptAesGcmWithTmk(byte[] cipherTextWithIvAndTag)
        {
            if (_tmk == null) throw new InvalidOperationException("TMK not available");
            byte[] iv = cipherTextWithIvAndTag[..12];
            byte[] cipherText = cipherTextWithIvAndTag[12..^16];
            byte[] tag = cipherTextWithIvAndTag[^16..];
            using var aes = new AesGcm(_tmk, 16);
            byte[] plain = new byte[cipherText.Length];
            aes.Decrypt(iv, cipherText, tag, plain);
            return plain;
        }

        public void StoreOperationalKeys(byte[] decryptedKeys)
        {
            Console.WriteLine($"   [PED] Operational keys received (length: {decryptedKeys.Length} bytes).");
        }
    }

    // ========== HSM Simulator (Server Side) ==========
    public class HsmSimulator
    {
        private readonly X509Certificate2 _caCert;
        private readonly RSA _serverPrivateKey;
        private readonly X509Certificate2 _serverCert;

        public HsmSimulator(X509Certificate2 caCert, RSA serverPrivateKey, X509Certificate2 serverCert)
        {
            _caCert = caCert;
            _serverPrivateKey = serverPrivateKey;
            _serverCert = serverCert;
        }

        public string GetServerCertBase64() => Convert.ToBase64String(_serverCert.Export(X509ContentType.Cert));

        public bool VerifyDeviceCert(X509Certificate2 deviceCert, out string error)
        {
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(_caCert);
                chain.ChainPolicy.ExtraStore.Add(_caCert);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool isValid = chain.Build(deviceCert);
                if (!isValid)
                {
                    error = "Certificate chain invalid: " + string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation));
                    return false;
                }
                error = "";
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public bool VerifyDeviceSignature(byte[] data, byte[] signature, X509Certificate2 deviceCert)
        {
            using var pubKey = deviceCert.GetRSAPublicKey();
            return pubKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public byte[] EncryptWithDevicePublic(byte[] plain, X509Certificate2 deviceCert)
        {
            using var pubKey = deviceCert.GetRSAPublicKey();
            return pubKey.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
        }

        public byte[] SignWithServerPrivate(byte[] data) =>
            _serverPrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        public (byte[] sessionKey, byte[] encryptedSessionKey) GenerateAndEncryptSessionKey(X509Certificate2 deviceCert)
        {
            byte[] sessionKey = RandomNumberGenerator.GetBytes(32);
            byte[] encryptedSessionKey = EncryptWithDevicePublic(sessionKey, deviceCert);
            return (sessionKey, encryptedSessionKey);
        }

        public byte[] EncryptWithAesGcm(byte[] plain, byte[] key)
        {
            byte[] iv = RandomNumberGenerator.GetBytes(12);
            var cipher = new byte[plain.Length];
            byte[] tag = new byte[16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(iv, plain, cipher, tag);
            byte[] result = new byte[iv.Length + cipher.Length + tag.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, result, iv.Length, cipher.Length);
            Buffer.BlockCopy(tag, 0, result, iv.Length + cipher.Length, tag.Length);
            return result;
        }
    }

    // ========== KDH Server ==========
    public class RkiServer
    {
        private readonly HsmSimulator _hsm;
        private readonly Dictionary<Guid, ServerSession> _sessions = new();

        private class ServerSession
        {
            public X509Certificate2 DeviceCert { get; set; }
            public byte[] Challenge { get; set; }
            public byte[] SessionKey { get; set; }
            public byte[] Tmk { get; set; }
        }

        public RkiServer(HsmSimulator hsm) => _hsm = hsm;

        public async Task<RkiResponse> ProcessRequestAsync(RkiRequest request)
        {
            if (request.Step == 1)
            {
                var deviceCert = new X509Certificate2(Convert.FromBase64String(request.DeviceCertB64));
                if (!_hsm.VerifyDeviceCert(deviceCert, out string err))
                    return new RkiResponse { SessionId = request.SessionId, Step = 1, Success = false, Error = err };

                byte[] challenge = RandomNumberGenerator.GetBytes(32);
                _sessions[request.SessionId] = new ServerSession { DeviceCert = deviceCert, Challenge = challenge };
                return new RkiResponse
                {
                    SessionId = request.SessionId,
                    Step = 1,
                    Success = true,
                    ChallengeB64 = Convert.ToBase64String(challenge)
                };
            }
            else if (request.Step == 2)
            {
                if (!_sessions.TryGetValue(request.SessionId, out var session))
                    return new RkiResponse { SessionId = request.SessionId, Step = 2, Success = false, Error = "Invalid session" };

                byte[] signature = Convert.FromBase64String(request.SignedChallengeB64);
                if (!_hsm.VerifyDeviceSignature(session.Challenge, signature, session.DeviceCert))
                    return new RkiResponse { SessionId = request.SessionId, Step = 2, Success = false, Error = "Challenge signature invalid" };

                return new RkiResponse
                {
                    SessionId = request.SessionId,
                    Step = 2,
                    Success = true,
                    ServerCertB64 = _hsm.GetServerCertBase64()
                };
            }
            else if (request.Step == 3)
            {
                if (!_sessions.TryGetValue(request.SessionId, out var session))
                    return new RkiResponse { SessionId = request.SessionId, Step = 3, Success = false, Error = "Invalid session" };

                byte[] clientNonce = Convert.FromBase64String(request.ClientNonceB64);
                byte[] serverSignature = _hsm.SignWithServerPrivate(clientNonce);
                var (sessionKey, encryptedSessionKey) = _hsm.GenerateAndEncryptSessionKey(session.DeviceCert);
                session.SessionKey = sessionKey;

                return new RkiResponse
                {
                    SessionId = request.SessionId,
                    Step = 3,
                    Success = true,
                    SignedChallengeB64 = Convert.ToBase64String(serverSignature),
                    EncryptedSessionKeyB64 = Convert.ToBase64String(encryptedSessionKey)
                };
            }
            else if (request.Step == 4)
            {
                if (!_sessions.TryGetValue(request.SessionId, out var session))
                    return new RkiResponse { SessionId = request.SessionId, Step = 4, Success = false, Error = "Invalid session" };

                byte[] tmk = RandomNumberGenerator.GetBytes(32);
                session.Tmk = tmk;
                byte[] encTmk = _hsm.EncryptWithAesGcm(tmk, session.SessionKey);
                return new RkiResponse
                {
                    SessionId = request.SessionId,
                    Step = 4,
                    Success = true,
                    EncryptedTmkB64 = Convert.ToBase64String(encTmk)
                };
            }
            else if (request.Step == 5)
            {
                if (!_sessions.TryGetValue(request.SessionId, out var session))
                    return new RkiResponse { SessionId = request.SessionId, Step = 5, Success = false, Error = "Invalid session" };

                byte[] operationalKeys = RandomNumberGenerator.GetBytes(64);
                byte[] encOps = _hsm.EncryptWithAesGcm(operationalKeys, session.Tmk);
                return new RkiResponse
                {
                    SessionId = request.SessionId,
                    Step = 5,
                    Success = true,
                    EncryptedOperationalKeysB64 = Convert.ToBase64String(encOps)
                };
            }
            else
                return new RkiResponse { SessionId = request.SessionId, Step = request.Step, Success = false, Error = "Unknown step" };
        }
    }

    // ========== Acquire Switch (Router) ==========
    public class AcquireSwitch
    {
        private readonly RkiServer _server;
        public AcquireSwitch(RkiServer server) => _server = server;
        public async Task<RkiResponse> SendAsync(RkiRequest request) => await _server.ProcessRequestAsync(request);
    }

    // ========== Client (POS) ==========
    public class RkiClient
    {
        private readonly PedSimulator _ped;
        private readonly AcquireSwitch _switch;
        private readonly Guid _sessionId = Guid.NewGuid();

        public RkiClient(PedSimulator ped, AcquireSwitch sw)
        {
            _ped = ped;
            _switch = sw;
        }

        public async Task<bool> RunRkiAsync()
        {
            Console.WriteLine($"\n=== RKI Started (Session: {_sessionId}) ===");

            // Step 1: Send device certificate and receive challenge
            var req1 = new RkiRequest { SessionId = _sessionId, Step = 1, DeviceCertB64 = _ped.GetDeviceCertBase64() };
            var resp1 = await _switch.SendAsync(req1);
            if (!resp1.Success) { Console.WriteLine($"Step 1 Error: {resp1.Error}"); return false; }
            byte[] challenge = Convert.FromBase64String(resp1.ChallengeB64);
            Console.WriteLine("Step 1: Device certificate verified, challenge received.");

            // Step 2: Sign challenge with device private key
            byte[] signature = _ped.SignData(challenge);
            var req2 = new RkiRequest { SessionId = _sessionId, Step = 2, SignedChallengeB64 = Convert.ToBase64String(signature) };
            var resp2 = await _switch.SendAsync(req2);
            if (!resp2.Success) { Console.WriteLine($"Step 2 Error: {resp2.Error}"); return false; }
            Console.WriteLine("Step 2: Challenge signature verified.");

            // Step 3: Mutual authentication & receive RSA-encrypted Session Key
            byte[] clientNonce = RandomNumberGenerator.GetBytes(32);
            var req3 = new RkiRequest { SessionId = _sessionId, Step = 3, ClientNonceB64 = Convert.ToBase64String(clientNonce) };
            var resp3 = await _switch.SendAsync(req3);
            if (!resp3.Success) { Console.WriteLine($"Step 3 Error: {resp3.Error}"); return false; }

            // Verify server signature on client nonce
            byte[] serverSig = Convert.FromBase64String(resp3.SignedChallengeB64);
            var serverCert = new X509Certificate2(Convert.FromBase64String(resp2.ServerCertB64));
            using var serverPubKey = serverCert.GetRSAPublicKey();
            if (!_ped.VerifySignature(clientNonce, serverSig, serverPubKey))
            {
                Console.WriteLine("Step 3 Error: Server signature invalid.");
                return false;
            }
            Console.WriteLine("Step 3: Mutual authentication successful.");

            // Decrypt Session Key using RSA private key
            byte[] encryptedSessionKey = Convert.FromBase64String(resp3.EncryptedSessionKeyB64);
            byte[] sessionKey = _ped.DecryptRsa(encryptedSessionKey);
            _ped.StoreSessionKey(sessionKey);

            // Step 4: Receive TMK encrypted with Session Key (AES-GCM)
            var req4 = new RkiRequest { SessionId = _sessionId, Step = 4 };
            var resp4 = await _switch.SendAsync(req4);
            if (!resp4.Success) { Console.WriteLine($"Step 4 Error: {resp4.Error}"); return false; }
            byte[] encryptedTmk = Convert.FromBase64String(resp4.EncryptedTmkB64);
            byte[] tmk = _ped.DecryptAesGcm(encryptedTmk);
            _ped.StoreTmk(tmk);

            // Step 5: Receive operational keys encrypted with TMK (AES-GCM)
            var req5 = new RkiRequest { SessionId = _sessionId, Step = 5 };
            var resp5 = await _switch.SendAsync(req5);
            if (!resp5.Success) { Console.WriteLine($"Step 5 Error: {resp5.Error}"); return false; }
            byte[] encryptedOps = Convert.FromBase64String(resp5.EncryptedOperationalKeysB64);
            byte[] opsKeys = _ped.DecryptAesGcmWithTmk(encryptedOps);
            _ped.StoreOperationalKeys(opsKeys);

            Console.WriteLine("=== RKI completed successfully ===\n");
            return true;
        }
    }

   
}