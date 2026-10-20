using System;
using System.Collections.Specialized;
using System.Web;

namespace BluntOTP
{
    public class OTP_URI
    {
        public string Scheme;
        public string Type;
        public string Label;
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

        public string Algorithm
        {
            get
            {
                return Parameters["algorithm"];
            }
        }

        public string Digits
        {
            get
            {
                return Parameters["digits"];
            }
        }

        public string Counter
        {
            get
            {
                return Parameters["counter"];
            }
        }

        public string Period
        {
            get
            {
                return Parameters["period"];
            }
        }

        public string Issuer_Parameter
        {
            get
            {
                return Parameters["issuer"];
            }
        }

        public static OTP_URI Parse(string input)
        {
            Uri URI = new Uri(input);

            OTP_URI Result = new OTP_URI();
            Result.Scheme = URI.Scheme;
            Result.Type = URI.Host;
            Result.Label = URI.LocalPath.TrimStart('/');
            if (Result.Label.Contains(":"))
            {
                Result.Issuer_Label = Result.Label.Substring(0, Result.Label.IndexOf(':'));
                Result.Account = Result.Label.Substring(Result.Issuer_Label.Length + 1);
            }
            else
            {
                Result.Account = Result.Label;
            }
            Result.Account = Result.Account.TrimStart(' ');
            Result.Parameters = HttpUtility.ParseQueryString(URI.Query);
            
            return Result;
        }
    }
}
