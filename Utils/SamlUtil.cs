using AuthCenter.Models;
using AuthCenter.Providers.IdProvider;
using AuthCenter.Utils.ExtendCryptography;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace AuthCenter.Utils
{
    public class SamlUtil
    {
        private readonly static XNamespace Samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
        private readonly static XNamespace Saml = "urn:oasis:names:tc:SAML:2.0:assertion";

        static SamlUtil()
        {
            CryptoConfig.AddAlgorithm(typeof(Ecdsa256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
            CryptoConfig.AddAlgorithm(typeof(XmlDsigC14NTransform), "http://www.w3.org/2006/12/xml-c14n11");

            // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.safecanonicalizationmethods
            // SafeCanonicalizationMethods behaves like a static property. Changes from one instance of SignedXml will be observed in other instances.
            // Modifying the collection is not a thread-safe operation.
            new SignedXml().SafeCanonicalizationMethods.Add("http://www.w3.org/2006/12/xml-c14n11");
        }

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
                    new XAttribute("entityID", frontEndUrl),
                    new XElement("{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor", new XAttribute(XNamespace.Xmlns + "md", "urn:oasis:names:tc:SAML:2.0:metadata"), new XAttribute(XNamespace.Xmlns + "ds", "http://www.w3.org/2000/09/xmldsig#"), new XAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol"),
                        keyDescriptor,
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
                        new XElement(md + "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),

                        new XElement(md + "SingleSignOnService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"), new XAttribute("Location", frontEndUrl + "/auth/login-saml/" + application.ClientId)),
                        new XElement(md + "SingleSignOnService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", frontEndUrl + "/api/saml/login-saml/" + application.ClientId), new XAttribute("isDefault", "true")),

                        new XElement(md + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"), new XAttribute("Location", frontEndUrl + "/api/logout-saml/" + application.ClientId)),
                        new XElement(md + "SingleLogoutService", new XAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"), new XAttribute("Location", frontEndUrl + "/api/logout-saml/" + application.ClientId))
                    )
                );

            var metaXmlDoc = new XDocument(entityDescriptor);

            return metaXmlDoc;
        }
        public static string GetSamlRequest(string frontEndUrl, string destination, string binding, string id, bool isCompressed)
        {
            var curTime = DateTime.UtcNow;
            var currentTimeStr = curTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var authnRequest = new XElement(Samlp + "AuthnRequest",
                new XAttribute("AssertionConsumerServiceURL", $"{frontEndUrl}/auth/callback"),
                new XAttribute("Destination", destination),
                new XAttribute("ForceAuthn", "false"),
                new XAttribute("ID", id),
                new XAttribute("IsPassive", "false"),
                new XAttribute("IssueInstant", currentTimeStr),
                new XAttribute("ProtocolBinding", binding),
                new XAttribute("Version", "2.0"),
                new XAttribute(XNamespace.Xmlns + "saml2p", "urn:oasis:names:tc:SAML:2.0:protocol"),
                new XElement(Saml + "Issuer", new XAttribute(XNamespace.Xmlns + "saml2", "urn:oasis:names:tc:SAML:2.0:assertion"), $"{frontEndUrl}/auth/callback")
                );

            var doc = new XDocument();
            doc.Add(authnRequest);

            var docXml = new XmlDocument();
            docXml.Load(doc.CreateReader());

            var declearation = docXml.CreateXmlDeclaration("1.0", "UTF-8", "");
            docXml.InsertBefore(declearation, docXml.FirstChild);

            var docBytes = Encoding.UTF8.GetBytes(docXml.InnerXml);
            if (isCompressed)
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

        public static XmlDocument GetRawSAMLResponse(User user, Application application,
            string url, string frontEndUrl, string redirectUrl,
            string requestIssuer, string id, bool isEncrypted, string? requestId)
        {
            var curTime = DateTime.UtcNow;

            var currentTimeStr = curTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var expiredTimeStr = curTime.AddSeconds(application.ExpiredSecond).ToString("yyyy-MM-ddTHH:mm:ssZ");

            var subjectConfirmationData = new XElement(Saml + "SubjectConfirmationData");
            if (requestId != null)
            {
                subjectConfirmationData.Add(new XAttribute("InResponseTo", requestId));
            }
            subjectConfirmationData.Add(new XAttribute("Recipient", redirectUrl), new XAttribute("NotOnOrAfter", expiredTimeStr));

            var attributeStatement = new XElement(Saml + "AttributeStatement");
            if (user.Email != null)
            {
                attributeStatement.Add(GetAttribute("Email", user.Email));
            }
            if (user.Phone != null)
            {
                attributeStatement.Add(GetAttribute("Phone", user.Phone));
            }
            if (user.Id != null)
            {
                attributeStatement.Add(GetAttribute("Username", user.Id));
            }
            if (user.Name != null)
            {
                attributeStatement.Add(GetAttribute("Name", user.Name));
            }

            foreach (var item in application.SamlAttributes)
            {
                if (item.Value.Contains("$user.Roles"))
                {
                    var roles = (from role in user.Roles select item.Value.Replace("$user.Roles", role)).ToArray();
                    attributeStatement.Add(GetAttribute(item.Name, item.NameFormat, roles));
                }

                if (item.Value.Contains("$user.Email"))
                {
                    XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
                    attributeStatement.Add(GetAttribute(item.Name, item.NameFormat, user.Email!));

                }

                if (item.Value.Contains("$user.Id"))
                {
                    XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
                    attributeStatement.Add(GetAttribute(item.Name, item.NameFormat, user.Id!));
                }
            }

            var assertion =
                new XElement(Saml + "Assertion",
                        new XAttribute(XNamespace.Xmlns + "xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                        new XAttribute(XNamespace.Xmlns + "xs", "http://www.w3.org/2001/XMLSchema"),
                        new XAttribute("ID", "_" + id),
                        new XAttribute(XNamespace.Xmlns + "saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
                        new XAttribute("IssueInstant", currentTimeStr),
                        new XAttribute("Version", "2.0"),

                        new XElement(Saml + "Issuer", url),
                        new XElement(Saml + "Subject",
                        new XElement(Saml + "NameID", new XAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), user.Id),
                        new XElement(Saml + "SubjectConfirmation", new XAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"), subjectConfirmationData)),
                        new XElement(Saml + "Conditions", new XAttribute("NotBefore", currentTimeStr), new XAttribute("NotOnOrAfter", expiredTimeStr),
                            new XElement(Saml + "AudienceRestriction",
                               //new XElement(Saml + "Audience", requestIssuer),
                               from aud in application.SamlAudiences select new XElement(Saml + "Audience", aud)
                            )
                        ),
                        new XElement(Saml + "AuthnStatement", new XAttribute("AuthnInstant", currentTimeStr),
                            new XAttribute("SessionIndex", id),
                            new XAttribute("SessionNotOnOrAfter", expiredTimeStr),
                            new XElement(Saml + "AuthnContext",
                                new XElement(Saml + "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
                            )
                        ),
                        attributeStatement
                    );

            var respId = Guid.NewGuid().ToString();
            var response =
                new XElement(Samlp + "Response",
                        new XAttribute(XNamespace.Xmlns + "samlp", "urn:oasis:names:tc:SAML:2.0:protocol"), new XAttribute(XNamespace.Xmlns + "saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
                        new XAttribute("ID", "_" + respId), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", currentTimeStr),
                        new XAttribute("Destination", redirectUrl), new XAttribute("InResponseTo", requestId ?? ""),
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
            XmlElement? xeAssertion = doc.DocumentElement!.SelectSingleNode("saml:Assertion", ns) as XmlElement;
            XmlElement? xeDoc = doc.DocumentElement;

            var x509Cert = application.Cert!.ToX509Certificate2();

            #region EncryptAssertion
            if (isEncrypted)
            {
                Aes sessionKey = Aes.Create();
                sessionKey.KeySize = 256;

                EncryptedXml eXml = new EncryptedXml();
                byte[] encryptedElement = eXml.EncryptData(xeAssertion!, sessionKey, false);

                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;

                edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);
                EncryptedKey ek = new EncryptedKey();
                byte[]? encryptedKey;
                if (application.Cert.CryptoAlgorithm == "RS")
                {
                    encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, x509Cert.GetRSAPublicKey()!, false);
                }
                else
                {
                    throw new Exception("Not supported key type");
                    //encryptedKey = 
                }

                ek.CipherData = new CipherData(encryptedKey);

                ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
                edElement.KeyInfo = new KeyInfo();
                KeyInfoName kin = new KeyInfoName();
                kin.Value = application.Cert.Name;
                ek.KeyInfo.AddClause(kin);
                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));
                edElement.CipherData.CipherValue = encryptedElement;

                XmlElement encryptedAssertion = doc.CreateElement("EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
                encryptedAssertion.AppendChild(doc.ImportNode(edElement.GetXml(), true));

                doc.DocumentElement.ReplaceChild(encryptedAssertion, xeAssertion!);
            }
            #endregion

            #region Sign Whole Response
            SignedXml? signedXml = null;
            if (application.Cert.CryptoAlgorithm == "RS")
            {
                signedXml = new(xeDoc!)
                {
                    SigningKey = x509Cert.GetRSAPrivateKey(),
                };
            }
            else
            {
                signedXml = new(xeDoc!)
                {
                    SigningKey = x509Cert.GetECDsaPrivateKey()
                };
            }

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(x509Cert));
            signedXml.KeyInfo = keyInfo;

            Reference reference = new()
            {
                Uri = "#_" + respId
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            XmlElement? xeIssuer = doc!.FirstChild!.SelectSingleNode("saml:Issuer", ns) as XmlElement;
            doc!.FirstChild!.InsertAfter(xmlDigitalSignature, xeIssuer);
            #endregion

            return doc;
        }

        public static string GetSAMLResponse(User user, Application application,
            string url, string frontEndUrl, string redirectUrl,
            string requestIssuer, string id, bool isEncrypted, string? requestId)
        {
            var doc = GetRawSAMLResponse(user, application, url, frontEndUrl, redirectUrl, requestIssuer, id, isEncrypted, requestId);

            #region Compress Response
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
            #endregion

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

        private static XElement GetAttribute(string name, string nameFormat, string value)
        {
            XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
            return new XElement(Saml + "Attribute", new XAttribute("Name", name), new XAttribute("NameFormat", nameFormat),
                    new XElement(Saml + "AttributeValue", new XAttribute(XNamespace.Xmlns + "xs", "http://www.w3.org/2001/XMLSchema"),
                        new XAttribute(XNamespace.Xmlns + "xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                        new XAttribute(xsi + "type", "xs:string"),
                        value
                    )
                );
        }

        private static XElement GetAttribute(string name, string nameFormat, string[] values)
        {
            XNamespace xsi = "http://www.w3.org/2001/XMLSchema-instance";
            return new XElement(Saml + "Attribute", new XAttribute("Name", name), new XAttribute("NameFormat", nameFormat),
                    from value in values
                    select new XElement(Saml + "AttributeValue", new XAttribute(XNamespace.Xmlns + "xs", "http://www.w3.org/2001/XMLSchema"),
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

            try
            {
                MemoryStream compressed = new(byteSamlRequest);
                MemoryStream decompressed = new();
                DeflateStream deflateStream = new(compressed, CompressionMode.Decompress);
                deflateStream.CopyTo(decompressed);
                byteSamlRequest = decompressed.ToArray();
            }
            catch
            {

            }
            var decodedSamlRequest = Encoding.UTF8.GetString(byteSamlRequest);

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

        public class SamlMetadata
        {
            public string EntityID { get; set; } = "";
            public string BindingType { get; set; } = "";
            public string Location { get; set; } = "";
            public string Cert { get; set; } = "";
        }

        public static SamlMetadata ParseSamlMetaData(string samlMetadata)
        {
            XDocument xmlDoc = XDocument.Parse(samlMetadata);

            var entityDescriptor = xmlDoc.Root;
            var entityId = entityDescriptor!.Attribute("entityID");

            XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
            var idpDescriptor = entityDescriptor.Descendants(md + "IDPSSODescriptor").FirstOrDefault();

            var singleSignOnService = idpDescriptor!.Elements(md + "SingleSignOnService")
                .Where(x => x.Attribute("isDefault")?.Value == "true").FirstOrDefault();
            if (singleSignOnService is null)
            {
                singleSignOnService = idpDescriptor!.Elements(md + "SingleSignOnService").First();
            }
            var binding = singleSignOnService.Attribute("Binding");
            var location = singleSignOnService.Attribute("Location");

            XNamespace sig = "http://www.w3.org/2000/09/xmldsig#";
            var x509Key = idpDescriptor.Descendants(sig + "X509Certificate").FirstOrDefault();

            return new SamlMetadata
            {
                EntityID = entityId!.Value,
                BindingType = binding!.Value,
                Location = location!.Value,
                Cert = x509Key!.Value,
            };
        }

        public static UserInfo ParseSamlResponseData(string samlResponse, string cert, string issuer, string url, UserInfoMap userInfoMap, out string requestId)
        {
            var byteSamlRequest = Convert.FromBase64String(samlResponse);
            var decodedSamlRequest = Encoding.UTF8.GetString(byteSamlRequest);
            var publicCert = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(cert));

            XmlDocument xmlDoc = new() { PreserveWhitespace = true, XmlResolver = null };

            xmlDoc.LoadXml(decodedSamlRequest);

            var statusCode = xmlDoc.GetElementsByTagName("StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
            if (statusCode == null)
            {
                throw new Exception("invalid status code");
            }

            var codeValue = statusCode[0]?.Attributes?["Value"]?.InnerText;
            if (codeValue != "urn:oasis:names:tc:SAML:2.0:status:Success")
            {
                throw new Exception(codeValue);
            }

            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            XmlNodeList nodeList = xmlDoc.SelectNodes("//ds:Signature", manager)!;

            SignedXml signedXml = new(xmlDoc);

            signedXml.LoadXml((XmlElement)nodeList[0]!);
            //signedXml.SafeCanonicalizationMethods.Add("http://www.w3.org/2006/12/xml-c14n11");
            var res = signedXml.CheckSignature(publicCert, true);

            if (res == false)
            {
                throw new Exception("Signature invlid");
            }

            var subjectConfirmationData = xmlDoc.GetElementsByTagName("SubjectConfirmationData", "urn:oasis:names:tc:SAML:2.0:assertion")[0];
            var requestIdXml = subjectConfirmationData?.Attributes?["InResponseTo"];
            if (requestIdXml == null)
            {
                throw new Exception("Require InResponseTo");
            }

            requestId = requestIdXml.InnerText;

            var notOnOrAfter = subjectConfirmationData?.Attributes?["NotOnOrAfter"];
            if (notOnOrAfter != null)
            {
                DateTimeOffset dateTimeOffset = DateTimeOffset.Parse(notOnOrAfter.InnerText);
                if (dateTimeOffset < DateTimeOffset.Now)
                {
                    throw new Exception("Expired request");
                }
            }

            var condition = xmlDoc.GetElementsByTagName("Conditions", "urn:oasis:names:tc:SAML:2.0:assertion")[0];
            var notBefore = condition?.Attributes?["NotBefore"];
            notOnOrAfter = condition?.Attributes?["NotOnOrAfter"];
            if (notBefore != null)
            {
                DateTimeOffset dateTimeOffset = DateTimeOffset.Parse(notBefore.InnerText);
                if (dateTimeOffset > DateTimeOffset.Now)
                {
                    throw new Exception("Not valid request");
                }
            }

            if (notOnOrAfter != null)
            {
                DateTimeOffset dateTimeOffset = DateTimeOffset.Parse(notOnOrAfter.InnerText);
                if (dateTimeOffset < DateTimeOffset.Now)
                {
                    throw new Exception("Expired request");
                }
            }

            var audiences = xmlDoc.GetElementsByTagName("Audience", "urn:oasis:names:tc:SAML:2.0:assertion");
            var find = false;
            foreach (XmlNode item in audiences)
            {
                if (item.InnerText == url)
                {
                    find = true;
                    break;
                }
            }

            if (!find)
            {
                throw new Exception("Not in audience list");
            }

            UserInfo userInfo = new UserInfo();

            var attributeList = xmlDoc.GetElementsByTagName("Attribute", "urn:oasis:names:tc:SAML:2.0:assertion");
            foreach (XmlNode item in attributeList)
            {
                var nameValue = item.Attributes?["Name"]?.InnerText;
                if (String.IsNullOrEmpty(nameValue))
                {
                    throw new Exception("AttributeValue parsed error");
                }

                if (nameValue == userInfoMap.Id) userInfo.Id = item.InnerText;
                else if (nameValue == userInfoMap.Name) userInfo.Name = item.InnerText;
                else if (nameValue == userInfoMap.PreferredName) userInfo.PreferredName = item.InnerText;
                else if (nameValue == userInfoMap.Email) userInfo.Email = item.InnerText;
                else if (nameValue == userInfoMap.Phone) userInfo.Phone = item.InnerText;
            }

            return userInfo;
        }
    }
}
