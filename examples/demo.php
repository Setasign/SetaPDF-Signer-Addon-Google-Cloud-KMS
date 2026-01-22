<?php

use setasign\SetaPDF\Signer\Module\GoogleCloudKMS\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\IntegrityResult;

require_once __DIR__ . '/../vendor/autoload.php';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$settings = require 'settings.php';
$projectId = $settings['projectId'];
$locationId = $settings['locationId'];
$keyRingId = $settings['keyRingId'];
$keyId = $settings['keyId'];
$versionId = $settings['versionId'];
$cert = $settings['cert'];
$digest = $settings['digest'];

$googleCloudKmsModule = new Module(
    $projectId,
    $locationId,
    $keyRingId,
    $keyId,
    $versionId
);

$googleCloudKmsModule->setCertificate($cert);
$googleCloudKmsModule->setDigest($digest);

// create a writer instance
$writer = new FileWriter($resultPath);
// create the document instance
$document = Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new Signer($document);
$fieldName = $signer->addSignatureField()->getQualifiedName();
$signer->setSignatureFieldName($fieldName);
$signer->sign($googleCloudKmsModule);

// verify the integrity to check if e.g. both private key and public key in the certificate match:
$document = Document::loadByFilename($resultPath);
$integrityResult = IntegrityResult::create($document, $fieldName);
var_dump($integrityResult->isValid() ? 'Valid' : 'Not Valid! Double check that the Certificate matches the private key!');
