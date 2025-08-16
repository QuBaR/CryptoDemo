using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        while (true)
        {
            Console.WriteLine("\n=== Krypteringsdemo (.NET) ===");
            Console.WriteLine("1) AES (symmetrisk, CBC)");
            Console.WriteLine("2) AES-GCM (symmetrisk, GCM)");
            Console.WriteLine("3) Jämför AES CBC och GCM");
            Console.WriteLine("4) RSA (asymmetrisk)");
            Console.WriteLine("5) Hybrid (AES + RSA)");
            Console.WriteLine("6) Filkryptering (AES-GCM)");
            Console.WriteLine("7) Benchmark: AES vs RSA");
            Console.WriteLine("8) Avsluta");
            Console.Write("Val: ");
            var choice = Console.ReadLine();

            if (choice == "8" || string.IsNullOrWhiteSpace(choice)) break;



            switch (choice)
            {
                case "1":
                case "2":
                case "3":
                case "4":
                case "5":
                case "7":
                    Console.Write("Ange klartext: ");
                    var plaintext = Console.ReadLine() ?? "";
                    if (choice == "1") DemoAes(plaintext);
                    else if (choice == "2") DemoAesGcm(plaintext);
                    else if (choice == "3") CompareAesCbcGcm(plaintext);
                    else if (choice == "4") DemoRsa(plaintext);
                    else if (choice == "5") DemoHybrid(plaintext);
                    else if (choice == "7") BenchmarkAesVsRsa(plaintext);
                    break;
                case "6":
                    FileEncryptionMenu();
                    break;
                default:
                    Console.WriteLine("Ogiltigt val.");
                    break;
            }

    // ===== BENCHMARK: AES vs RSA =====
    static void BenchmarkAesVsRsa(string plaintext)
    {
        var sw = new System.Diagnostics.Stopwatch();
        Console.WriteLine("\n[Benchmark: AES-256 CBC]");
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        sw.Start();
        var cipher = AesEncrypt(plaintext, aes.Key, aes.IV);
        sw.Stop();
        PrintLabelValue("Kryptering (ms)", sw.Elapsed.TotalMilliseconds.ToString("F2"));
        sw.Restart();
        var roundtrip = AesDecrypt(cipher, aes.Key, aes.IV);
        sw.Stop();
        PrintLabelValue("Dekryptering (ms)", sw.Elapsed.TotalMilliseconds.ToString("F2"));

        Console.WriteLine("\n[Benchmark: RSA-2048]");
        using var rsa = RSA.Create(2048);
        var data = Encoding.UTF8.GetBytes(plaintext);
        sw.Restart();
        var cipherRsa = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        sw.Stop();
        PrintLabelValue("Kryptering (ms)", sw.Elapsed.TotalMilliseconds.ToString("F2"));
        sw.Restart();
        var roundtripRsa = rsa.Decrypt(cipherRsa, RSAEncryptionPadding.OaepSHA256);
        sw.Stop();
        PrintLabelValue("Dekryptering (ms)", sw.Elapsed.TotalMilliseconds.ToString("F2"));
    }
    // ===== FILKRYPTERING MED AES-GCM =====
    static void FileEncryptionMenu()
    {
        Console.WriteLine("\n[Filkryptering med AES-GCM]");
        Console.Write("Ange filväg: ");
        var path = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
        {
            Console.WriteLine("Ogiltig filväg.");
            return;
        }
        Console.Write("Kryptera (K) eller Dekryptera (D)? ");
        var mode = Console.ReadLine()?.Trim().ToUpperInvariant();
        Console.Write("Ange lösenord: ");
        var password = Console.ReadLine();
        if (string.IsNullOrEmpty(password))
        {
            Console.WriteLine("Lösenord krävs.");
            return;
        }
        if (mode == "K")
        {
            var outPath = path + ".aesgcm";
            try
            {
                EncryptFileAesGcm(path, outPath, password);
                Console.WriteLine($"Filen krypterad: {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid kryptering: {ex.Message}");
            }
        }
        else if (mode == "D")
        {
            var outPath = path.EndsWith(".aesgcm") ? path.Substring(0, path.Length - 7) : path + ".decrypted";
            try
            {
                DecryptFileAesGcm(path, outPath, password);
                Console.WriteLine($"Filen dekrypterad: {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid dekryptering: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine("Ogiltigt val. Ange K eller D.");
        }
    }

    static void EncryptFileAesGcm(string inPath, string outPath, string password)
    {
        var salt = new byte[16];
        var nonce = new byte[12];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        rng.GetBytes(nonce);
        var key = DeriveKeyFromPassword(password, salt, 32);
        var plain = System.IO.File.ReadAllBytes(inPath);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Encrypt(nonce, plain, cipher, tag);
        }
        // Spara: [salt][nonce][tag][cipher]
        using var fs = System.IO.File.Create(outPath);
        fs.Write(salt, 0, salt.Length);
        fs.Write(nonce, 0, nonce.Length);
        fs.Write(tag, 0, tag.Length);
        fs.Write(cipher, 0, cipher.Length);
    }

    static void DecryptFileAesGcm(string inPath, string outPath, string password)
    {
        var all = System.IO.File.ReadAllBytes(inPath);
        var salt = new byte[16];
        var nonce = new byte[12];
        var tag = new byte[16];
        Buffer.BlockCopy(all, 0, salt, 0, 16);
        Buffer.BlockCopy(all, 16, nonce, 0, 12);
        Buffer.BlockCopy(all, 28, tag, 0, 16);
        var cipher = new byte[all.Length - 44];
        Buffer.BlockCopy(all, 44, cipher, 0, cipher.Length);
        var key = DeriveKeyFromPassword(password, salt, 32);
        var plain = new byte[cipher.Length];
        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Decrypt(nonce, cipher, tag, plain);
        }
        System.IO.File.WriteAllBytes(outPath, plain);
    }

    static byte[] DeriveKeyFromPassword(string password, byte[] salt, int keyBytes)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        return kdf.GetBytes(keyBytes);
    }
    // ===== SYMMETRISK: AES-GCM =====
    static void DemoAesGcm(string plaintext)
    {
        using var rng = RandomNumberGenerator.Create();
        var key = new byte[32]; // 256-bit
        var nonce = new byte[12]; // 96-bit nonce recommended for GCM
        rng.GetBytes(key);
        rng.GetBytes(nonce);

        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[plainBytes.Length];
        var tag = new byte[16]; // 128-bit tag

        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Encrypt(nonce, plainBytes, cipher, tag);
        }

        // Decrypt to verify
        var decrypted = new byte[plainBytes.Length];
        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Decrypt(nonce, cipher, tag, decrypted);
        }
        var roundtrip = Encoding.UTF8.GetString(decrypted);

        Console.WriteLine("\n[AES-GCM]");
        PrintLabelValue("Key (Base64)", Convert.ToBase64String(key));
        PrintLabelValue("Nonce (Base64)", Convert.ToBase64String(nonce));
        PrintLabelValue("Ciphertext", Convert.ToBase64String(cipher));
        PrintLabelValue("Tag", Convert.ToBase64String(tag));
        PrintLabelValue("Dekrypterat", roundtrip);
    }

    // ===== JÄMFÖR AES CBC OCH GCM =====
    static void CompareAesCbcGcm(string plaintext)
    {
        Console.WriteLine("\n--- Jämförelse: AES CBC vs AES-GCM ---");
        Console.WriteLine("\n[AES CBC]");
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        var cipherCbc = AesEncrypt(plaintext, aes.Key, aes.IV);
        var roundtripCbc = AesDecrypt(cipherCbc, aes.Key, aes.IV);
        PrintLabelValue("Key (Base64)", Convert.ToBase64String(aes.Key));
        PrintLabelValue("IV  (Base64)", Convert.ToBase64String(aes.IV));
        PrintLabelValue("Ciphertext", Convert.ToBase64String(cipherCbc));
        PrintLabelValue("Dekrypterat", roundtripCbc);

        Console.WriteLine("\n[AES-GCM]");
        var key = aes.Key; // Use same key for fair comparison
        using var rng = RandomNumberGenerator.Create();
        var nonce = new byte[12];
        rng.GetBytes(nonce);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherGcm = new byte[plainBytes.Length];
        var tag = new byte[16];
        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Encrypt(nonce, plainBytes, cipherGcm, tag);
        }
        var decrypted = new byte[plainBytes.Length];
        using (var aesgcm = new AesGcm(key, tag.Length))
        {
            aesgcm.Decrypt(nonce, cipherGcm, tag, decrypted);
        }
        var roundtripGcm = Encoding.UTF8.GetString(decrypted);
        PrintLabelValue("Key (Base64)", Convert.ToBase64String(key));
        PrintLabelValue("Nonce (Base64)", Convert.ToBase64String(nonce));
        PrintLabelValue("Ciphertext", Convert.ToBase64String(cipherGcm));
        PrintLabelValue("Tag", Convert.ToBase64String(tag));
        PrintLabelValue("Dekrypterat", roundtripGcm);
    }
        }
    }

    // ===== SYMMETRISK: AES =====
    static void DemoAes(string plaintext)
    {
        using var aes = Aes.Create(); // AES-256 om KeySize = 256
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        var cipher = AesEncrypt(plaintext, aes.Key, aes.IV);
        var roundtrip = AesDecrypt(cipher, aes.Key, aes.IV);

    Console.WriteLine("\n[AES]");
    PrintLabelValue("Key (Base64)", Convert.ToBase64String(aes.Key));
    PrintLabelValue("IV  (Base64)", Convert.ToBase64String(aes.IV));
    PrintLabelValue("Ciphertext", Convert.ToBase64String(cipher));
    PrintLabelValue("Dekrypterat", roundtrip);
    }

    static byte[] AesEncrypt(string plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var enc = aes.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        return enc.TransformFinalBlock(bytes, 0, bytes.Length);
    }

    static string AesDecrypt(byte[] cipher, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var dec = aes.CreateDecryptor();
        var plainBytes = dec.TransformFinalBlock(cipher, 0, cipher.Length);
        return Encoding.UTF8.GetString(plainBytes);
    }

    // ===== ASYMMETRISK: RSA =====
    static void DemoRsa(string plaintext)
    {
        using var rsa = RSA.Create(2048);

        // Exportera nycklar (PKCS#8 privat, SubjectPublicKeyInfo publik)
        var pub = rsa.ExportSubjectPublicKeyInfo();
        var priv = rsa.ExportPkcs8PrivateKey();

        var cipher = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), RSAEncryptionPadding.OaepSHA256);
        var roundtrip = Encoding.UTF8.GetString(rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256));

    Console.WriteLine("\n[RSA]");
    PrintLabelValue("Public Key  (Base64)", Convert.ToBase64String(pub));
    PrintLabelValue("Private Key (Base64)", Convert.ToBase64String(priv));
    PrintLabelValue("Ciphertext", Convert.ToBase64String(cipher));
    PrintLabelValue("Dekrypterat", roundtrip);
    }

    // ===== HYBRID: AES + RSA =====
    static void DemoHybrid(string plaintext)
    {
        // 1) Generera slumpad AES-nyckel + IV
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        // 2) Kryptera data med AES
        var cipher = AesEncrypt(plaintext, aes.Key, aes.IV);

        // 3) Kryptera AES-nyckel + IV med RSA (för säker nyckeldistribution)
        using var rsa = RSA.Create(2048);
        var keyPackage = Combine(aes.Key, aes.IV); // paketera key+iv
        var wrappedKey = rsa.Encrypt(keyPackage, RSAEncryptionPadding.OaepSHA256);

    Console.WriteLine("\n[HYBRID AES+RSA]");
    PrintLabelValue("AES Key (Base64)", Convert.ToBase64String(aes.Key));
    PrintLabelValue("AES IV  (Base64)", Convert.ToBase64String(aes.IV));
    PrintLabelValue("Ciphertext", Convert.ToBase64String(cipher));
    PrintLabelValue("Wrapped Key", Convert.ToBase64String(wrappedKey));

        // 4) Visa att dekryptering funkar: "mottagaren" använder privat nyckel
        var unwrapped = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        var (key2, iv2) = Split(unwrapped, aes.Key.Length);
    var roundtrip = AesDecrypt(cipher, key2, iv2);
    PrintLabelValue("Dekrypterat", roundtrip);
    // Helper to print label and value with clear distinction and color
    static void PrintLabelValue(string label, string value)
    {
        var oldColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"{label,-20}: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(value);
        Console.ForegroundColor = oldColor;
    }
    }

    // Hjälpfunktioner för att paketera Key+IV
    static byte[] Combine(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    static (byte[] first, byte[] second) Split(byte[] src, int firstLen)
    {
        var a = new byte[firstLen];
        var b = new byte[src.Length - firstLen];
        Buffer.BlockCopy(src, 0, a, 0, firstLen);
        Buffer.BlockCopy(src, firstLen, b, 0, b.Length);
        return (a, b);
    }

    // Helper to print label and value with clear distinction and color
    static void PrintLabelValue(string label, string value)
    {
        var oldColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"{label,-20}: ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(value);
        Console.ForegroundColor = oldColor;
    }
}
