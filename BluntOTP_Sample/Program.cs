using System;

namespace BluntOTP_Sample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Seed for HMAC-SHA1 - 20 bytes
            String Seed = "3132333435363738393031323334353637383930";

            // Seed for HMAC-SHA256 - 32 bytes
            String Seed32 = "3132333435363738393031323334353637383930313233343536373839303132";

            // Seed for HMAC-SHA512 - 64 bytes
            String Seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

            long T0 = 0;
            int X = 30;
            long[] testTime = new long[] { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };

            string format = "| {0,15} | {1,25} | {2,10} | {3,10} |";
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
