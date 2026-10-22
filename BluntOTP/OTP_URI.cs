using System;
using System.Collections.Specialized;
using System.Linq;
using System.Web;

namespace BluntOTP
{
    public class OTP_URI
    {
        public string Scheme;
        public string Type;
        public string Label;
        // The issuer label prefix (issuer-label) is presentation-oriented text
        // for display.
        public string Issuer_Label;
        public string Account;

        public NameValueCollection Parameters;

        public string Secret
        {
            get
            {
                return Parameters["secret"];
            }
        }

        // The issuer parameter (issuer) is the canonical identifier for account
        // matching.
        public string Issuer_Parameter
        {
            get
            {
                return Parameters["issuer"];
            }
        }

        public string Algorithm
        {
            get
            {
                return Parameters["algorithm"];
            }
        }

        public int Digits
        {
            get
            {
                return Convert.ToInt32(Parameters["digits"]);
            }
        }

        public int Period
        {
            get
            {
                return Convert.ToInt32(Parameters["period"]);
            }
        }

        public long Counter
        {
            get
            {
                return Convert.ToInt32(Parameters["counter"]);
            }
        }

        public static OTP_URI Parse(string input)
        {
            Uri URI = new Uri(input);

            OTP_URI Result = new OTP_URI();
            Result.Scheme = URI.Scheme;
            Result.Type = URI.Host;
            Result.Label = URI.LocalPath.TrimStart('/');
            // If label contains a separator, split the raw string at the first
            // separator, where separator is either literal : or percent-encoded
            // %3A (case-insensitive).
            if (Result.Label.Contains(":"))
            {
                Result.Issuer_Label = Result.Label.Substring(0, Result.Label.IndexOf(':'));
                Result.Account = Result.Label.Substring(Result.Issuer_Label.Length + 1);
            }
            // If label does not contain a separator, treat the entire label as
            // account.
            else
            {
                Result.Account = Result.Label;
            }
            // optional spaces before account are encoded as %20
            Result.Account = Result.Account.TrimStart(' ');
            Result.Parameters = HttpUtility.ParseQueryString(URI.Query);
            
            return Result;
        }

        public bool IsValid()
        {
            if (!Scheme.Equals("otpauth", StringComparison.InvariantCultureIgnoreCase))
                return false;

            // otp-type identifies the OTP method and MUST be either totp or
            // hotp.
            if (!Type.Equals("hotp", StringComparison.InvariantCultureIgnoreCase) &&
                !Type.Equals("totp", StringComparison.InvariantCultureIgnoreCase))
                return false;

            // issuer-label and account MUST NOT themselves contain a colon
            if (Label.Split(':').Length > 2)
                // If decoded issuer-label or decoded account contains a colon,
                // the consumer MUST reject the URI.
                return false;

            // A producer MAY include algorithm, digits, counter, period, and
            // issuer
            string[] KnownParameters = new string[] { "secret", "algorithm", "digits", "counter", "period", "issuer" };
            foreach (string Parameter in Parameters.AllKeys.Where(x => KnownParameters.Contains(x)))
            {
                // each known parameter MUST appear at most once.
                if (Parameters.GetValues(Parameter).Length > 1)
                {
                    // A consumer MUST reject the URI if any known parameter
                    // appears more than once
                    return false;
                }
            }

            // A consumer MUST reject the URI if secret is missing.
            if (String.IsNullOrEmpty(Secret))
                return false;

            // algorithm is OPTIONAL. If absent, the default is SHA1.
            if (!String.IsNullOrEmpty(Algorithm) &&
               // Valid algorithm values are SHA1, SHA256, and SHA512.
               (!Algorithm.Equals("SHA1", StringComparison.InvariantCultureIgnoreCase) &&
                !Algorithm.Equals("SHA256", StringComparison.InvariantCultureIgnoreCase) &&
                !Algorithm.Equals("SHA512", StringComparison.InvariantCultureIgnoreCase)))
            {
                // If a consumer receives an unsupported algorithm value, it
                // SHOULD reject the URI.
                return false;
            }

            // digits is OPTIONAL. If absent, the default is 6.
            if (!String.IsNullOrEmpty(Parameters["digits"]) &&
               // Valid digits values are 6 and 8.
               (Digits < 6 ||
                Digits > 8))
            {
                // If a consumer receives an unsupported digits value, it SHOULD
                // reject the URI.
                return false;
            }

            // period is OPTIONAL for totp. If absent, the default is 30.
            if ((!String.IsNullOrEmpty(Parameters["period"]) && Type.Equals("totp", StringComparison.InvariantCultureIgnoreCase)) &&
               (Period != 15 &&
                Period != 30 &&
                Period != 60))
            {
                return false;
            }

            // counter is REQUIRED for hotp and MUST be ignored for totp.
            if (Type.Equals("hotp", StringComparison.InvariantCultureIgnoreCase) && String.IsNullOrEmpty(Parameters["counter"]))
            {
                return false;
            }

            return true;
        }
    }
}
