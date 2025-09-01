using AuthCenter.Models;
using System.Xml;
using System.Xml.Serialization;

namespace AuthCenter.ViewModels.Response
{
    [XmlType(Namespace = "http://www.yale.edu/tp/cas")]
    [XmlRoot("serviceResponse", Namespace = "http://www.yale.edu/tp/cas", IsNullable = false)]
    public class ServiceResponse
    {
        public static XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
        static ServiceResponse()
        {
            ns.Add("cas", "http://www.yale.edu/tp/cas");
        }

        public class CasProxies
        {
            [XmlArrayItem("proxy")]
            public string[] Proxy { get; set; } = [];
        }

        public class CasAttributes
        {
            [XmlElement("authenticationDate", Namespace = "http://www.yale.edu/tp/cas")]
            public DateTime AuthencationDate { get; set; }
            [XmlElement("longTermAuthenticationRequestTokenUsed", Namespace = "http://www.yale.edu/tp/cas")]
            public bool LongTermAuthenticationRequestTokenUsed { get; set; }
            [XmlElement("isFromNewLogin", Namespace = "http://www.yale.edu/tp/cas")]
            public bool IsFromNewLogin { get; set; }
            [XmlElement("memberOf", Namespace = "http://www.yale.edu/tp/cas")]
            public string[] MemberOf { get; set; } = [];
            [XmlElement("userAttributes", Namespace = "http://www.yale.edu/tp/cas")]
            public User UserAttributes { get; set; } = default!;
        }

        public class CasAuthenticationSuccess
        {
            [XmlElement("user", Namespace = "http://www.yale.edu/tp/cas")]
            public string User { get; set; } = "";

            [XmlElement("proxyGrantingTicket", Namespace = "http://www.yale.edu/tp/cas")]
            public string? ProxyGrantingTicket { get; set; }

            [XmlArray("proxies", Namespace = "http://www.yale.edu/tp/cas")]
            [XmlArrayItem("proxy")]
            public List<string>? Proxies { get; set; } = [];

            [XmlElement("attributes", Namespace = "http://www.yale.edu/tp/cas")]
            public CasAttributes CasAttributes { get; set; } = default!;

            [XmlElement("service", Namespace = "http://www.yale.edu/tp/cas")]
            public string? Service { get; set; }
        }

        public class CasAuthenticationFailure
        {
            [XmlAttribute("code")]
            public string Code { get; set; } = "";

            [XmlText]
            public string Message { get; set; } = "";
        }

        public class CasProxySuccess
        {
            [XmlElement("proxyTicket")]
            public string ProxyTicket { get; set; } = "";
        }

        [XmlElement("authenticationSuccess", Namespace = "http://www.yale.edu/tp/cas")]
        public CasAuthenticationSuccess? AuthenticationSuccess { get; set; }

        [XmlElement("authenticationFailure", Namespace = "http://www.yale.edu/tp/cas")]
        public CasAuthenticationFailure? AuthenticationFailure { get; set; }

        [XmlElement("proxyFailure", Namespace = "http://www.yale.edu/tp/cas")]
        public CasAuthenticationFailure? ProxyFailure { get; set; }

        [XmlElement("proxySuccess", Namespace = "http://www.yale.edu/tp/cas")]
        public CasProxySuccess? ProxySuccess { get; set; }

        public string ToXml()
        {
            using StringWriter sw = new();
            var sr = new XmlSerializer(this.GetType());
            sr.Serialize(sw, this, ns);
            return sw.ToString();
        }

        public static ServiceResponse? FromXml(string xml)
        {
            var sr = new XmlSerializer(typeof(ServiceResponse));
            using StringReader sreader = new StringReader(xml);
            return sr.Deserialize(sreader) as ServiceResponse;
        }
    }
}
