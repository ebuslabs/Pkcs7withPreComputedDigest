
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using BCX509 = Org.BouncyCastle.X509;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Text;

namespace Pkcs7withPreComputedDigest
{
    class Program
    {
        #region Variables

        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        private Pkcs11 _pkcs11 = null;

        /// <summary>
        /// Logical reader with token used for signing
        /// </summary>
        private Slot _slot = null;

        /// <summary>
        /// Master session where user is logged in
        /// </summary>
        private Session _session = null;

        /// <summary>
        /// Handle of private key used for signing 
        /// </summary>
        private ObjectHandle _privateKeyHandle = null;

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key used for signing
        /// </summary>
        private string _ckaLabel = null;

        /// <summary>
        /// Identifier (value of CKA_ID attribute) of the private key used for signing
        /// </summary>
        private byte[] _ckaId = null;

        /// <summary>
        /// Hash algorihtm used for the signature creation
        /// </summary>
        private HashAlgorithm _hashAlgorihtm = HashAlgorithm.SHA256;

        /// <summary>
        /// Raw data of certificate related to private key used for signing
        /// </summary>
        private byte[] _signingCertificate = null;

        /// <summary>
        /// Raw data of all certificates stored in device
        /// </summary>
        private List<byte[]> _allCertificates = null;

        #endregion

        static void Main(string[] args)
        {
            var data = "abc";
            IDigest hashGenerator = GetHashGenerator(HashAlgorithm.SHA256);
            byte[] dataHash = ComputeDigest(hashGenerator, Encoding.UTF8.GetBytes(data));

            // import signing certificate in X509 format
            // import certificate chain in X509 format (collection)

            //Call GenerateSignature
        }

        /// <summary>
        /// Generates PKCS#7 signature of specified data
        /// </summary>
        /// <param name="precomputedHash">Data to be signed</param>
        /// <param name="detached">Flag indicating whether detached signature should be produced</param>
        /// <param name="signingCertificate">Signing certificate</param>
        /// <param name="certPath">Certification path for signing certificate</param>
        /// <returns>DER encoded PKCS#7 signature of specified data</returns>
        public byte[] GenerateSignature(byte[] precomputedHash, BCX509.X509Certificate signingCertificate, ICollection<BCX509.X509Certificate> certPath)
        {

            string hashOid = GetHashOid(_hashAlgorihtm);
            IDigest hashGenerator = GetHashGenerator(_hashAlgorihtm);

            // Construct SignerInfo.signedAttrs
            Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

            // Add PKCS#9 contentType signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(OID.PKCS9AtContentType),
                    new DerSet(new DerObjectIdentifier(OID.PKCS7IdData))));

            // Add Pre Computed messageDigest attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(OID.PKCS9AtMessageDigest),
                    new DerSet(new DerOctetString(precomputedHash))));

            // Add PKCS#9 signingTime signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    new DerObjectIdentifier(OID.PKCS9AtSigningTime),
                    new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

            DerSet signedAttributes = new DerSet(signedAttributesVector);

            // Sign SignerInfo.signedAttrs with PKCS#1 v1.5 RSA signature using private key stored on PKCS#11 compatible device
            byte[] pkcs1Digest = ComputeDigest(hashGenerator, signedAttributes.GetDerEncoded());
            byte[] pkcs1DigestInfo = CreateDigestInfo(pkcs1Digest, hashOid);
            byte[] pkcs1Signature = null;

            using (Session session = _slot.OpenSession(true))
            using (Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS))
                pkcs1Signature = session.Sign(mechanism, _privateKeyHandle, pkcs1DigestInfo);

            // Construct SignerInfo
            SignerInfo signerInfo = new SignerInfo(
                new SignerIdentifier(new IssuerAndSerialNumber(signingCertificate.IssuerDN, signingCertificate.SerialNumber)),
                new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null),
                signedAttributes,
                new AlgorithmIdentifier(new DerObjectIdentifier(OID.PKCS1RsaEncryption), null),
                new DerOctetString(pkcs1Signature),
                null);

            // Construct SignedData.digestAlgorithms
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(new AlgorithmIdentifier(new DerObjectIdentifier(hashOid), null));

            // ** Set Data as null
            ContentInfo encapContentInfo = new ContentInfo(new DerObjectIdentifier(OID.PKCS7IdData), null);

            // Construct SignedData.certificates
            Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
            foreach (BCX509.X509Certificate cert in certPath)
                certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

            // Construct SignedData.signerInfos
            Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
            signerInfosVector.Add(signerInfo.ToAsn1Object());

            // Construct SignedData
            SignedData signedData = new SignedData(
                new DerSet(digestAlgorithmsVector),
                encapContentInfo,
                new BerSet(certificatesVector),
                null,
                new DerSet(signerInfosVector));

            // Construct top level ContentInfo
            ContentInfo contentInfo = new ContentInfo(
                new DerObjectIdentifier(OID.PKCS7IdSignedData),
                signedData);

            return contentInfo.GetDerEncoded();
        }

        /// <summary>
        /// Returns OID of specified hash algorithm
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>OID of specified hash algorithm</returns>
        private static string GetHashOid(HashAlgorithm hashAlgorithm)
        {
            string oid = null;

            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    oid = OID.SHA1;
                    break;
                case HashAlgorithm.SHA256:
                    oid = OID.SHA256;
                    break;
                case HashAlgorithm.SHA384:
                    oid = OID.SHA384;
                    break;
                case HashAlgorithm.SHA512:
                    oid = OID.SHA512;
                    break;
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }

            return oid;
        }

        /// <summary>
        /// Returns implementation of specified hash algorithm
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>Implementation of specified hash algorithm</returns>
        private static IDigest GetHashGenerator(HashAlgorithm hashAlgorithm)
        {
            IDigest digest = null;

            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    digest = new Sha1Digest();
                    break;
                case HashAlgorithm.SHA256:
                    digest = new Sha256Digest();
                    break;
                case HashAlgorithm.SHA384:
                    digest = new Sha384Digest();
                    break;
                case HashAlgorithm.SHA512:
                    digest = new Sha512Digest();
                    break;
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }

            return digest;
        }

        /// <summary>
        /// Computes hash of the data
        /// </summary>
        /// <param name="digest">Hash algorithm implementation</param>
        /// <param name="data">Data that should be processed</param>
        /// <returns>Hash of data</returns>
        private static byte[] ComputeDigest(IDigest digest, byte[] data)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] hash = new byte[digest.GetDigestSize()];

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }


        /// <summary>
        /// Creates PKCS#1 DigestInfo
        /// </summary>
        /// <param name="hash">Hash value</param>
        /// <param name="hashOid">Hash algorithm OID</param>
        /// <returns>DER encoded PKCS#1 DigestInfo</returns>
        private static byte[] CreateDigestInfo(byte[] hash, string hashOid)
        {
            DerObjectIdentifier derObjectIdentifier = new DerObjectIdentifier(hashOid);
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(derObjectIdentifier, null);
            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, hash);
            return digestInfo.GetDerEncoded();
        }
    }
}
