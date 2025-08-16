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
            Console.WriteLine("1) AES (symmetrisk)");
            Console.WriteLine("2) RSA (asymmetrisk)");
            Console.WriteLine("3) Hybrid (AES + RSA)");
            Console.WriteLine("4) Avsluta");
            Console.Write("Val: ");
            var choice = Console.ReadLine();

            if (choice == "4" || string.IsNullOrWhiteSpace(choice)) break;

            Console.Write("Ange klartext: ");
            var plaintext = Console.ReadLine() ?? "";

            switch (choice)
            {
                case "1":
                    DemoAes(plaintext);
                    break;
                case "2":
                    DemoRsa(plaintext);
                    break;
                case "3":
                    DemoHybrid(plaintext);
                    break;
                default:
                    Console.WriteLine("Ogiltigt val.");
                    break;
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
