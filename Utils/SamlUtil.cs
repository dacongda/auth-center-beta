using AuthCenter.Models;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace AuthCenter.Utils
{
    public class SamlUtil
    {
        private static XNamespace Samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
        private static XNamespace Saml = "urn:oasis:names:tc:SAML:2.0:assertion";

        public static XDocument GetSAMLMetadata(string url, string frontEndUrl, Application application)
        {
            if (application.Cert == null)
            {
                throw new ArgumentNullException();
            }

            XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
            XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
            XNamespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";
            var keyDescriptor =
                new XElement(md + "KeyDescriptor", new XAttribute("use", "signing"),
                    new XElement("{http://www.w3.org/2000/09/xmldsig#}KeyInfo", new XAttribute(XNamespace.Xmlns + "ds", "http://www.w3.org/2000/09/xmldsig#"),
                        new XElement("{http://www.w3.org/2000/09/xmldsig#}X509Data",
                            new XElement("{http://www.w3.org/2000/09/xmldsig#}X509Certificate", application.Cert.Certificate ?? ""))
                        )
                    );

            var entityDescriptor =
                new XElement(md + "EntityDescriptor",
                    new XAttribute("entityID", url),
                    new XElement("{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor", new XAttribute(XNamespace.Xmlns + "md", "urn:oasis:names:tc:SAML:2.0:metadata"), new XAttribute(XNamespace.Xmlns + "ds", "http://www.w3.org/2000/09/xmldsig#"), new XAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol"),
                        keyDescriptor,
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),

                        new XElement(md + "SingleSignOnService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"), new XAttribute("Location", frontEndUrl + "/auth/login-saml/" + application.ClientId)),
                        new XElement(md + "SingleSignOnService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", frontEndUrl + "/auth/login-saml/" + application.ClientId), new XAttribute("isDefault", "true")),

                        new XElement(md + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"), new XAttribute("Location", frontEndUrl + "/api/logout-saml/" + application.ClientId)),
                        new XElement(md + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", frontEndUrl + "/api/logout-saml/" + application.ClientId))
                    )
                );

            var metaXmlDoc = new XDocument(entityDescriptor);

            return metaXmlDoc;
        }

        public static string GetSAMLResponse(User user, Application application, string url, string frontEndUrl, string redirectUrl, string requestIssuer, string id, string? requestId)
        {
            var curTime = DateTime.UtcNow;

            var currentTimeStr = curTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var expiredTimeStr = curTime.AddSeconds(application.ExpiredSecond).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var subjectConfirmationData = new XElement(Saml + "SubjectConfirmationData", new XAttribute("NotOnOrAfter", currentTimeStr), new XAttribute("Recipient", redirectUrl));
            if (requestId != null)
            {
                subjectConfirmationData.Add(new XAttribute("InResponseTo", requestId));
            }

            var attributeStatement = new XElement(Saml + "AttributeStatement");
            if (user.Email != null)
            {
                attributeStatement.Add(GetAttribute("email", user.Email));
            }
            if (user.Phone != null)
            {
                attributeStatement.Add(GetAttribute("email", user.Phone));
            }
            if (user.Number != null)
            {
                attributeStatement.Add(GetAttribute("username", user.Number));
            }
            if (user.Name != null)
            {
                attributeStatement.Add(GetAttribute("name", user.Name));
            }

            var assertion =
                new XElement(Saml + "Assertion",
                        new XAttribute("ID", "_" + id),
                        new XAttribute(XNamespace.Xmlns + "xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                        new XAttribute(XNamespace.Xmlns + "xs", "http://www.w3.org/2001/XMLSchema"),
                        new XAttribute(XNamespace.Xmlns + "saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
                        new XAttribute("IssueInstant", currentTimeStr),
                        new XAttribute("Version", "2.0"),

                        new XElement(Saml + "Issuer", url),
                        new XElement(Saml + "Subject",
                        new XElement(Saml + "NameID", new XAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), user.Email),
                        new XElement(Saml + "SubjectConfirmation", new XAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"), subjectConfirmationData)),
                        new XElement(Saml + "Conditions", new XAttribute("NotBefore", currentTimeStr), new XAttribute("NotOnOrAfter", expiredTimeStr),
                            new XElement(Saml + "AudienceRestriction",
                               new XElement(Saml + "Audience", requestIssuer)
                            )
                        ),
                        new XElement(Saml + "AuthnStatement", new XAttribute("AuthnInstant", currentTimeStr),
                            new XElement(Saml + "AuthnContext",
                                new XElement(Saml + "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
                            )
                        ),
                        attributeStatement
                    );

            var response =
                new XElement(Samlp + "Response",
                        new XAttribute(XNamespace.Xmlns + "samlp", "urn:oasis:names:tc:SAML:2.0:protocol"), new XAttribute(XNamespace.Xmlns + "saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
                        new XAttribute("ID", "_" + Guid.NewGuid().ToString()), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", currentTimeStr),
                    new XElement(Saml + "Issuer", url),
                    new XElement(Samlp + "Status",
                        new XElement(Samlp + "StatusCode", new XAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success"))
                    ),
                    assertion
                );

            var doc = new XmlDocument();
            doc.Load(response.CreateReader());


            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            XmlElement xeAssertion = doc.DocumentElement.SelectSingleNode("saml:Assertion", ns) as XmlElement;

            SignedXml? signedXml = null;
            var x509Cert = application.Cert.ToX509Certificate2();
            if (application.Cert.CryptoAlgorithm == "RS")
            {
                signedXml = new(xeAssertion)
                {
                    SigningKey = x509Cert.GetRSAPrivateKey()
                };
            }
            else
            {
                signedXml = new(xeAssertion)
                {
                    SigningKey = x509Cert.GetECDsaPrivateKey()
                };
            }

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;

            Reference reference = new();

            reference.Uri = "#_" + id;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            XmlElement xeIssuer = xeAssertion.SelectSingleNode("saml:Issuer", ns) as XmlElement;
            xeAssertion.InsertAfter(xmlDigitalSignature, xeIssuer);

            var docBytes = Encoding.UTF8.GetBytes(doc.InnerXml);
            if (application.SamlResponseCompress)
            {
                var ms = new MemoryStream(docBytes) { Position = 0 };
                var outMs = new MemoryStream();
                using (var deflateStream = new DeflateStream(outMs, CompressionMode.Compress, true))
                {
                    var buf = new byte[1024];
                    int len;
                    while ((len = ms.Read(buf, 0, buf.Length)) > 0)
                        deflateStream.Write(buf, 0, len);
                }
                docBytes = outMs.ToArray();
            }

            var encodedRes = Convert.ToBase64String(docBytes);
            return encodedRes;
        }

        private static XElement GetAttribute(string name, string value)
        {
            XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
            return new XElement(Saml + "Attribute", new XAttribute("Name", name), new XAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"),
                    new XElement(Saml + "AttributeValue", new XAttribute(XNamespace.Xmlns + "xs", "http://www.w3.org/2001/XMLSchema"),
                        new XAttribute(XNamespace.Xmlns + "xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                        new XAttribute(xsi + "type", "xs:string"),
                        value
                    )
                );
        }

        public class SamlRequest
        {
            public string AssertionConsumerServiceURL { get; set; } = "";
            public string Destination { get; set; } = "";
            public string ID { get; set; } = "";
            public string IsPassive { get; set; } = "";
            public string IssueInstant { get; set; } = "";
            public string ProtocolBinding { get; set; } = "";
            public string Issuer { get; set; } = "";
        }


        public static SamlRequest ParseSamlRequest(string samlRequest)
        {
            var byteSamlRequest = Convert.FromBase64String(samlRequest);

            MemoryStream compressed = new MemoryStream(byteSamlRequest);
            MemoryStream decompressed = new MemoryStream();
            DeflateStream deflateStream = new DeflateStream(compressed, CompressionMode.Decompress);
            deflateStream.CopyTo(decompressed);
            var decodedSamlRequestByte = decompressed.ToArray();
            var decodedSamlRequest = Encoding.UTF8.GetString(decodedSamlRequestByte);

            XDocument xmlDoc = XDocument.Parse(decodedSamlRequest);
            var assertionConsumerServiceURL = xmlDoc.Root?.Attribute("AssertionConsumerServiceURL");
            var destination = xmlDoc.Root?.Attribute("Destination");
            var id = xmlDoc.Root?.Attribute("ID");
            var issueInstant = xmlDoc.Root?.Attribute("IssueInstant");
            var protocolBinding = xmlDoc.Root?.Attribute("ProtocolBinding");

            XNamespace saml2 = "urn:oasis:names:tc:SAML:2.0:assertion";
            var issuer = xmlDoc.Root?.Element(saml2 + "Issuer");

            return new SamlRequest
            {
                AssertionConsumerServiceURL = assertionConsumerServiceURL?.Value ?? "",
                Destination = destination?.Value ?? "",
                ID = id?.Value ?? "",
                IssueInstant = issueInstant?.Value ?? "",
                ProtocolBinding = protocolBinding?.Value ?? "",
                Issuer = issuer?.Value ?? ""
            };
        }
    }
}
