using System;
using System.Collections.Generic;

namespace BluntOTP_Sample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            List<string> testURI = new List<string>
            {
                "otpauth://hotp/aboutinfosec.com:melon.ask?issuer=aboutinfosec.com&secret=S7OOPXNAMLWTDF6N7HAC3BJJTEJJQLZ3&algorithm=SHA1&digits=6&counter=10",
                "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
                "otpauth://totp/otpauth%20demo:username%40example.org?secret=AAAABBBB22223333YYYYZZZZ66667777&issuer=otpauth.dev",
                "otpauth://totp/Example%3Aalice?secret=PB4XU&issuer=example.com",
                "otpauth://hotp/Example?secret=PB4XU&counter=42&issuer=example.com",
                "otpauth://totp/ietfuser?secret=NBSWY3DPFQQHO33SNRSAU",
                "otpauth://hotp/13tfus3r?secret=NBSWY3DP&counter=192",
            };

            BluntOTP.OTP_URI example = new BluntOTP.OTP_URI();
            example.Type = "hotp";
            example.Issuer_Label = "BluntOTP";
            example.Account = "example@domain.tld";
            example.Issuer_Parameter = "https://github.com/unpaid/BluntOTP";
            example.Secret = "ABCDEFGH";
            example.Counter = 67;

            string exampleURI = example.Serialize();
            Console.WriteLine($"Example OTP URI: {exampleURI}");
            Console.WriteLine();

            testURI.Add( exampleURI );

            for (int i = 0; i < testURI.Count; i++)
            {
                var URI = BluntOTP.OTP_URI.Parse(testURI[i]);
                if (URI.IsValid())
                {
                    Console.WriteLine($"{URI.Account}{(!String.IsNullOrEmpty(URI.Issuer_Label) ? $" - {URI.Issuer_Label}" : String.Empty)}{(!String.IsNullOrEmpty(URI.Issuer_Parameter) ? $" ({URI.Issuer_Parameter})" : String.Empty)}");
                    Console.WriteLine($"\tType: {URI.Type}");
                    if (URI.Digits > 0)
                        Console.WriteLine($"\tDigits: {URI.Digits}");
                    if (!String.IsNullOrEmpty(URI.Algorithm))
                        Console.WriteLine($"\tAlgorithm: {URI.Algorithm}");
                    Console.WriteLine($"\tSecret (Base32): {URI.Secret}");
                    var secret = BluntOTP.Base32.Decode(URI.Secret);
                    if (URI.Type.Equals("hotp", StringComparison.InvariantCultureIgnoreCase))
                    {
                        Console.WriteLine($"\tCounter: {URI.Counter}");
                        Console.WriteLine($"\tCode: {BluntOTP.OTP.GenerateHOTP(secret, URI.Counter,
                            URI.Digits > 0 ? URI.Digits : 6,
                            !String.IsNullOrEmpty(URI.Algorithm) ? URI.Algorithm : "SHA1")}");
                    }
                    else if (URI.Type.Equals("totp", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (URI.Period > 0)
                            Console.WriteLine($"\tPeriod: {URI.Period}");
                        Console.WriteLine($"\tTime: {DateTimeOffset.Now.ToUniversalTime().ToUnixTimeSeconds()}");
                        Console.WriteLine($"\tCode: {BluntOTP.OTP.GenerateTOTP(secret,
                            URI.Period > 0 ? URI.Period : 30,
                            URI.Digits > 0 ? URI.Digits : 6,
                            !String.IsNullOrEmpty(URI.Algorithm) ? URI.Algorithm : "SHA1")}");
                    }
                }
                else
                {
                    Console.WriteLine($"Invalid OTP URI: {testURI[i]}");
                }
                Console.WriteLine();
            }

            // Seed for HMAC-SHA1 - 20 bytes
            string Seed = "3132333435363738393031323334353637383930";

            // Seed for HMAC-SHA256 - 32 bytes
            string Seed32 = "3132333435363738393031323334353637383930313233343536373839303132";

            // Seed for HMAC-SHA512 - 64 bytes
            string Seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

            string format = "| {0,10} | {1,10} |";
            Console.WriteLine(String.Format(format, "Count", "HOTP"));
            for (long counter = 0; counter < 10; counter++)
            {
                Console.WriteLine(String.Format(format, counter, BluntOTP.OTP.GenerateHOTP(Convert.FromHexString(Seed), counter)));
            }

            Console.WriteLine();

            long T0 = 0;
            int X = 30;
            long[] testTime = new long[] { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };

            format = "| {0,15} | {1,25} | {2,10} | {3,10} |";
            Console.WriteLine(String.Format(format, "Time (sec)", "UTC Time", "TOTP", "Mode"));
            for (int i = 0; i < testTime.Length; i++)
            {
                Console.WriteLine(String.Format(format, testTime[i],
                    DateTimeOffset.FromUnixTimeSeconds(testTime[i]).ToString("u"),
                    BluntOTP.OTP.GenerateTOTP(Convert.FromHexString(Seed), testTime[i], X, 8, "SHA1"),
                    "SHA1"));

                Console.WriteLine(String.Format(format, testTime[i],
                    DateTimeOffset.FromUnixTimeSeconds(testTime[i]).ToString("u"),
                    BluntOTP.OTP.GenerateTOTP(Convert.FromHexString(Seed32), testTime[i], X, 8, "SHA256"),
                    "SHA256"));

                Console.WriteLine(String.Format(format, testTime[i],
                    DateTimeOffset.FromUnixTimeSeconds(testTime[i]).ToString("u"),
                    BluntOTP.OTP.GenerateTOTP(Convert.FromHexString(Seed64), testTime[i], X, 8, "SHA512"),
                    "SHA512"));

            }

            Console.ReadLine();
        }
    }
}
