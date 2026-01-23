<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\GoogleCloudKMS;

use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\AsymmetricSignRequest;
use Google\Cloud\Kms\V1\CryptoKeyVersion\CryptoKeyVersionAlgorithm;
use Google\Cloud\Kms\V1\Client\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\Digest as KmsDigest;
use Google\Cloud\Kms\V1\GetCryptoKeyVersionRequest;
use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Oid as Asn1Oid;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Core\Reader\FilePath;
use setasign\SetaPDF2\Signer\Signature\Module\DictionaryInterface;
use setasign\SetaPDF2\Signer\Signature\Module\DocumentInterface;
use setasign\SetaPDF2\Signer\Signature\Module\ModuleInterface;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\Signature\Module\PadesProxyTrait;

class Module implements
    ModuleInterface,
    DictionaryInterface,
    DocumentInterface
{
    use PadesProxyTrait;

    /**
     * @var KeyManagementServiceClient
     */
    protected $kmsClient;

    /**
     * @var string
     */
    protected $keyVersionName;

    /**
     * @var int|null
     */
    protected $signatureAlgorithm;

    /**
     * Module constructor.
     *
     * @param string $projectId
     * @param string $locationId
     * @param string $keyRingId
     * @param string $keyId
     * @param string $versionId
     * @param KeyManagementServiceClient|null $kmsClient
     */
    public function __construct(
        $projectId,
        $locationId,
        $keyRingId,
        $keyId,
        $versionId,
        ?KeyManagementServiceClient $kmsClient = null
    ) {
        if ($kmsClient === null) {
            // Create the Cloud KMS client.
            $kmsClient = new KeyManagementServiceClient();
        }
        $this->kmsClient = $kmsClient;

        $this->keyVersionName = KeyManagementServiceClient::cryptoKeyVersionName(
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
     * Set the digest algorithm to use when signing.
     *
     * @param string $digest Allowed values are sha256, sha386, sha512
     * @see Pades::setDigest()
     */
    public function setDigest($digest)
    {
        $this->_getPadesModule()->setDigest($digest);
    }

    /**
     * Get the digest algorithm.
     *
     * @return string
     */
    public function getDigest()
    {
        return $this->_getPadesModule()->getDigest();
    }

    /**
     * Note: This method is optional. If no signature algorithm is given it will be fetched through the api which will
     * add a bit of extra execution time. You should ensure that the algorithm do match to the certificate
     * otherwise the signature could be invalid.
     *
     * @param int $signatureAlgorithm
     * @see CryptoKeyVersionAlgorithm
     */
    public function setSignatureAlgorithm($signatureAlgorithm)
    {
        $this->signatureAlgorithm = (int)$signatureAlgorithm;
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
    public function fetchSignatureAlgorithm()
    {
        $request = (new GetCryptoKeyVersionRequest())->setName($this->keyVersionName);
        return $this->kmsClient->getCryptoKeyVersion($request)->getAlgorithm();
    }

    /**
     * @inheritDoc
     */
    public function createSignature(FilePath $tmpPath)
    {
        $module = $this->_getPadesModule();
        $digest = $module->getDigest();
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
            if ($signatureAlgorithm === CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512) {
                $saltLength = 512 / 8;
            } else {
                $saltLength = 256 / 8;
            }

            $cms = $module->getCms();

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
                                        Asn1Oid::encode(Digest::getOid($digest))
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
                                                Asn1Oid::encode(Digest::getOid($digest))
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
        $hashData = $module->getDataToSign($tmpPath);

        $hash = \hash($digest, $hashData, true);
        $digestValue = new KmsDigest();
        switch ($digest) {
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

        $request = (new AsymmetricSignRequest)
            ->setName($this->keyVersionName)
            ->setDigest($digestValue);

        $signResponse = $this->kmsClient->asymmetricSign($request);

        // pass it to the module
        $module->setSignatureValue((string) $signResponse->getSignature());
        return (string) $module->getCms();
    }
}
