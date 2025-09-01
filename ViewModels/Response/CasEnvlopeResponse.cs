using System.Xml;
using System.Xml.Serialization;

namespace AuthCenter.ViewModels.Response
{
    [XmlType(Namespace = "http://schemas.xmlsoap.org/soap/envelope/")]
    [XmlRoot("Envelope", Namespace = "http://schemas.xmlsoap.org/soap/envelope/", IsNullable = false)]
    public class CasEnvlopeResponse
    {
        public static XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
        static CasEnvlopeResponse()
        {
            ns.Add("Envelope", "http://schemas.xmlsoap.org/soap/envelope/");
        }

        public class CasSamlInnerResponse
        {
            [XmlElement]
            public XmlElement Response { get; set; } = default!;
        }

        [XmlElement("Body", Namespace = "http://schemas.xmlsoap.org/soap/envelope/")]
        public CasSamlInnerResponse Body { get; set; } = default!;

        public string ToXml()
        {
            using StringWriter sw = new();
            var sr = new XmlSerializer(this.GetType());
            sr.Serialize(sw, this, ns);
            return sw.ToString();
        }
    }
}
