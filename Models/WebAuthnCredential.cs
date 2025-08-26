using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthCenter.Models
{
    [Index(nameof(UserId))]
    public class WebAuthnCredential : BaseModelWithoutId
    {
        [Key]
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required byte[] PublicKey { get; set; }
        public required string UserId { get; set; }
        public uint SignCount { get; set; } = 0;
        public AuthenticatorTransport[] Transports { get; set; } = [];
        public bool IsBackupEligible { get; set; }
        public bool IsBackedUp { get; set; }
        public byte[]? AttestationObject { get; set; }
        public byte[]? AttestationClientDataJson { get; set; }
        public DateTimeOffset RegDate { get; set; }
        public Guid AaGuid { get; set; }
        [NotMapped]
        public PublicKeyCredentialDescriptor Descriptor => new(PublicKeyCredentialType.PublicKey, Convert.FromBase64String(Id), Transports);
    }
}
