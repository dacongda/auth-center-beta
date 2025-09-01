using AuthCenter.Models;
using AuthCenter.ViewModels.Response;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace AuthCenter.Utils
{
    public class CasUtils
    {

        public static ServiceResponse GenerateServiceResponse(User user, string proxyGrantingTicket, string? service, bool newLogin)
        {
            var groups = user.Group?.ParentChain.Split("/") ?? [];

            var resp = new ServiceResponse()
            {
                AuthenticationSuccess = new ServiceResponse.CasAuthenticationSuccess
                {
                    User = user.Id,

                    ProxyGrantingTicket = proxyGrantingTicket,
                    CasAttributes = new ServiceResponse.CasAttributes
                    {
                        AuthencationDate = DateTime.Now,
                        LongTermAuthenticationRequestTokenUsed = true,
                        IsFromNewLogin = newLogin,
                        MemberOf = groups,
                        UserAttributes = user.GetMaskedUser()
                    }
                }
            };

            return resp;
        }
    }
}
