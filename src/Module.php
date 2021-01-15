<?php

/**
 * @copyright Copyright (c) 2021 Setasign - Jan Slabon (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GoogleCloudKMS;

use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\CryptoKeyVersion\CryptoKeyVersionAlgorithm;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\Digest as KmsDigest;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Core_Document as Document;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_Pades;

class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var KeyManagementServiceClient
     */
    protected $kmsClient;

    /**
     * @var SetaPDF_Signer_Signature_Module_Pades Internal pades module.
     */
    protected $padesModule;

    /**
     * @var string
     */
    protected $keyVersionName;

    /**
     * @var int|null
     */
    protected $signatureAlgorithm;

    public function __construct(
        string $projectId,
        string $locationId,
        string $keyRingId,
        string $keyId,
        string $versionId
    ) {
        // Create the Cloud KMS client.
        $this->kmsClient = new KeyManagementServiceClient();
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();

        $this->keyVersionName = $this->kmsClient->cryptoKeyVersionName(
            $projectId,
            $locationId,
            $keyRingId,
            $keyId,
            $versionId
        );
    }

    public function __destruct()
    {
        $this->kmsClient->close();
    }

    /**
     * @param $certificate
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate)
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * Set the digest algorithm to use when signing.
     *
     * @param string $digest Allowed values are sha256, sha386, sha512
     * @see SetaPDF_Signer_Signature_Module_Pades::setDigest()
     */
    public function setDigest(string $digest)
    {
        $this->padesModule->setDigest($digest);
    }

    /**
     * Get the digest algorithm.
     *
     * @return string
     */
    public function getDigest(): string
    {
        return $this->padesModule->getDigest();
    }

    /**
     * Note: This method is optional. If no signature algorithm is given it will be fetched through the api which will
     * add a little bit of extra execution time. You should ensure that the algorithm do match to the certificate
     * otherwise the signature could be invalid.
     *
     * @param int $signatureAlgorithm
     * @see CryptoKeyVersionAlgorithm
     */
    public function setSignatureAlgorithm(int $signatureAlgorithm)
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * @return int|null
     * @see CryptoKeyVersionAlgorithm
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @return int
     * @throws ApiException
     */
    public function fetchSignatureAlgorithm(): int
    {
        $keyVersion = $this->kmsClient->getCryptoKeyVersion($this->keyVersionName);
        return $keyVersion->getAlgorithm();
    }

    /**
     * @inheritDoc
     */
    public function updateSignatureDictionary(SetaPDF_Core_Type_Dictionary $dictionary)
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(Document $document)
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return Asn1Element
     * @throws SetaPDF_Signer_Exception
     */
    public function getCms()
    {
        return $this->padesModule->getCms();
    }

    /**
     * @inheritDoc
     */
    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        // ensure certificate
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            throw new \BadMethodCallException('Missing certificate!');
        }

        $padesDigest = $this->padesModule->getDigest();
        $signatureAlgorithm = $this->signatureAlgorithm;
        if ($signatureAlgorithm === null) {
            $signatureAlgorithm = $this->fetchSignatureAlgorithm();
        }

        $algorithmsWithPssPadding = [
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512
        ];
        // update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
        if (\in_array($signatureAlgorithm, $algorithmsWithPssPadding, true)) {
            // the algorihms are linked to https://tools.ietf.org/html/rfc7518#section-3.5 which says:
            // "The size of the salt value is the same size as the hash function output."
            $saltLength = 256 / 8;
            if ($signatureAlgorithm === CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256) {
                $saltLength = 384 / 8;
            } elseif (
                $signatureAlgorithm === CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256
                || $signatureAlgorithm === CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512
            ) {
                $saltLength = 512 / 8;
            }

            $cms = $this->padesModule->getCms();

            $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
            $signatureAlgorithmIdentifier->getChild(0)->setValue(
                Asn1Oid::encode("1.2.840.113549.1.1.10")
            );
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
            $signatureAlgorithmIdentifier->addChild(new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode(Digest::getOid($padesDigest))
                                    ),
                                    new Asn1Element(Asn1Element::NULL)
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new Asn1Element(
                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                        '',
                                        [
                                            new Asn1Element(
                                                Asn1Element::OBJECT_IDENTIFIER,
                                                Asn1Oid::encode(Digest::getOid($padesDigest))
                                            ),
                                            new Asn1Element(Asn1Element::NULL)
                                        ]
                                    )
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02",
                        '',
                        [
                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                        ]
                    )
                ]
            ));
        }

        // get the hash data from the module
        $hashData = $this->padesModule->getDataToSign($tmpPath);

        $hash = hash($padesDigest, $hashData, true);
        $digestValue = new KmsDigest();
        switch ($padesDigest) {
            case Digest::SHA_256:
                $digestValue->setSha256($hash);
                break;
            case Digest::SHA_384:
                $digestValue->setSha384($hash);
                break;
            case Digest::SHA_512:
                $digestValue->setSha512($hash);
                break;
        }

        $signResponse = $this->kmsClient->asymmetricSign($this->keyVersionName, $digestValue);

        // pass it to the module
        $this->padesModule->setSignatureValue((string) $signResponse->getSignature());
        return (string) $this->padesModule->getCms();
    }
}
