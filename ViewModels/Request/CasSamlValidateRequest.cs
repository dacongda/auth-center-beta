using AuthCenter.ViewModels.Response;
using System.Xml;
using System.Xml.Serialization;

namespace AuthCenter.ViewModels.Request
{
    [XmlType(Namespace = "http://schemas.xmlsoap.org/soap/envelope/")]
    [XmlRoot("Envelope", Namespace = "http://schemas.xmlsoap.org/soap/envelope/", IsNullable = false)]
    public class CasSamlValidateRequest
    {
        
        public class CasSamlInnerRequest
        {
            [XmlAttribute("RequestID")]
            public string RequestID { get; set; } = "";

            [XmlAttribute("IssueInstant")]
            public DateTime IssueInstant { get; set; }

            [XmlElement("AssertionArtifact")]
            public string AssertionArtiface { get; set; } = "";

        }

        public class CasSamlValidateBody
        {
            [XmlElement("Request", Namespace = "urn:oasis:names:tc:SAML:1.0:protocol")]
            public CasSamlInnerRequest CasSamlRequest { get; set; } = default!;
        }

        [XmlAnyElement("Header", Namespace = "http://schemas.xmlsoap.org/soap/envelope/")]
        public XmlElement Header { get; set; } = default!;
        [XmlElement("Body", Namespace = "http://schemas.xmlsoap.org/soap/envelope/")]
        public CasSamlValidateBody Body { get; set; } = default!;

        public static CasSamlValidateRequest? FromXml(string xml)
        {
            var sr = new XmlSerializer(typeof(CasSamlValidateRequest));
            using StringReader sreader = new StringReader(xml);
            return sr.Deserialize(sreader) as CasSamlValidateRequest;
        }
    }
}
