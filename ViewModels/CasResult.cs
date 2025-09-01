using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Xml.Serialization;
using AuthCenter.ViewModels.Response;
using System.Text;

namespace AuthCenter.ViewModels
{
    public class CasResult
    {
        public static ContentResult GetFailResponse(string code, string message, string? format)
        {
            return GetResponse(new ServiceResponse
            {
                AuthenticationFailure = new ServiceResponse.CasAuthenticationFailure
                {
                    Code = code,
                    Message = message
                }
            }, format);
        }

        public sealed class ExtentedStringWriter : StringWriter
        {
            private readonly Encoding stringWriterEncoding;
            public ExtentedStringWriter(StringBuilder builder, Encoding desiredEncoding)
                : base(builder)
            {
                this.stringWriterEncoding = desiredEncoding;
            }

            public override Encoding Encoding
            {
                get
                {
                    return this.stringWriterEncoding;
                }
            }
        }

        public static ContentResult GetResponse<T>(T obj, string? format)
        {
            format ??= "xml";
            string resp = "";
            if (format == "xml")
            {
                using ExtentedStringWriter sw = new(new StringBuilder(), Encoding.UTF8);
                var sr = new XmlSerializer(typeof(T));
                sr.Serialize(sw, obj, ServiceResponse.ns);

                resp = sw.ToString();
            }
            else
            {
                resp = JsonSerializer.Serialize(obj);
            }

            return new ContentResult
            {
                Content = resp,
                ContentType = format == "xml" ? "text/xml" : "text/json",
                StatusCode = 200,
            };
        }
    }
}
